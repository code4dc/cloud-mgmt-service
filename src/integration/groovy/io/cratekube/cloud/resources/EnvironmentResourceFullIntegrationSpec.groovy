package io.cratekube.cloud.resources

import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider
import com.sun.istack.internal.logging.Logger
import groovy.util.logging.Slf4j
import io.cratekube.cloud.model.Environment
import io.dropwizard.jackson.Jackson
import org.glassfish.jersey.client.ClientConfig
import org.glassfish.jersey.client.JerseyClientBuilder
import org.testcontainers.containers.BindMode
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.images.AlwaysPullPolicy
import org.testcontainers.images.ImagePullPolicy
import org.testcontainers.spock.Testcontainers
import org.testcontainers.utility.MountableFile
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider
import software.amazon.awssdk.services.ec2.Ec2Client
import software.amazon.awssdk.services.ec2.model.*
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Stepwise

import javax.ws.rs.NotFoundException
import javax.ws.rs.client.Client
import javax.ws.rs.core.GenericType
import javax.ws.rs.core.HttpHeaders

import static io.cratekube.cloud.model.Status.APPLIED
import static io.cratekube.cloud.model.Status.PENDING
import static javax.ws.rs.client.Entity.json
import static org.glassfish.jersey.client.ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.hasSize
import static org.hamcrest.core.IsNull.notNullValue
import static spock.util.matcher.HamcrestSupport.expect

@Stepwise
@Slf4j
@Testcontainers
class EnvironmentResourceFullIntegrationSpec extends Specification {
  static final TEST_ENV_NAME = 'test-env'
  static final TEST_BEARER_TOKEN = 'Bearer 6bc6a857-f61e-415b-be0d-aee5a0982164'
  String containerUrl
  String containerPort

  @Shared
  String awsKeyPairName
  String configDir = '/app/config'

  GenericContainer cloudMgmtService = new GenericContainer<>("cratekube/cloud-mgmt-service:latest")
    .withExposedPorts(9000)
    .withFileSystemBind('cratekube-data', configDir)
    .withImagePullPolicy(new AlwaysPullPolicy()).withEnv(['AWS_ACCESS_KEY_ID'    : "${System.getenv('AWS_ACCESS_KEY_ID')}".toString(),
                                                          'AWS_SECRET_ACCESS_KEY': "${System.getenv('AWS_SECRET_ACCESS_KEY')}".toString(),
                                                          'ADMIN_APIKEY'         : '6bc6a857-f61e-415b-be0d-aee5a0982164',
                                                          'CONFIG_DIR'           : "${configDir}".toString(),
                                                          'AWS_KEYPAIR_NAME'     : "auto_integration_test_${UUID.randomUUID()}".toString()
  ])

  @Shared
  Client client

  @Shared
  Ec2Client ec2

  def setup() {
    client = JerseyClientBuilder.createClient(
      new ClientConfig().with {
        property SUPPRESS_HTTP_COMPLIANCE_VALIDATION, 'true'
        register new JacksonJsonProvider(Jackson.newObjectMapper())
      }
    )
    awsKeyPairName = cloudMgmtService.getEnvMap()['AWS_KEYPAIR_NAME']

    ec2 = Ec2Client.builder()
      .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
      .build()

    containerUrl = cloudMgmtService.host
    containerPort = cloudMgmtService.firstMappedPort

    def logConsumer = new Slf4jLogConsumer(log)
    cloudMgmtService.followOutput(logConsumer)

    // Remove existing test env from AWS if it exists
    deleteExistingTestEnv()

    // Create CrateKube key pair
    createCrateKubeKeyPair()
  }

  void cleanupSpec() {
      deleteCrateKubeKeyPair()
  }

  void createCrateKubeKeyPair() {
    def createKeyPairRequest = CreateKeyPairRequest.builder().keyName(awsKeyPairName).build()
    def createKeyPairResult = ec2.createKeyPair(createKeyPairRequest)
    log.debug("{} KeyPair created with result {}", awsKeyPairName, createKeyPairResult)
  }

  void deleteCrateKubeKeyPair() {
    def deleteKeyPairRequest = DeleteKeyPairRequest.builder().keyName(awsKeyPairName).build()
    def deleteKeypairResult = ec2.deleteKeyPair(deleteKeyPairRequest)
    log.debug("{} KeyPair deleted with result {}", awsKeyPairName, deleteKeypairResult)
  }

  def 'cloud-mgmt-service should return empty environment list'() {
    when:
    def response = apiRequest()
      .get(new GenericType<List<Environment>>() {})

    then:
    verifyAll(response) {
      expect it, notNullValue()
      expect it, hasSize(0)
    }
  }

  def 'should create new CrateKube environment'() {
    given:
    // Get all Resource in AWS prior to environment initialization
    def existingEc2Instances = getCrateKubeEc2Instances()
    def existingVpcInstances = getCrateKubeVpcInstances()
    def existingSubnets = getCrateKubeSubnets()
    def existingInternetGateways = getCrateKubeInternetGateways()
    def existingRouteTables = getCrateKubeRouteTables()
    def existingSecurityGroups = getCrateKubeSecurityGroups()

    when:
    def response = apiRequest()
      .post(json(new EnvironmentResource.EnvironmentRequest(TEST_ENV_NAME)))

    def getEnvResponse
    def attempts = 0
    do {
      if (attempts > 0) {
        sleep 10000
      }
      getEnvResponse = apiRequest(TEST_ENV_NAME).get(new GenericType<Environment>() {})

      attempts++
      log.debug 'Attempt #{} to retrieve updated AWS resources with response: {}', attempts, getEnvResponse
    } while (attempts < 20 && getEnvResponse.status == PENDING )

    // Retrieve updated AWS Resources after environment initialization hsa begun
    def updatedEc2Instances = getCrateKubeEc2Instances()
    def updatedVpcInstances = getCrateKubeVpcInstances()
    def updatedSubnets = getCrateKubeSubnets()
    def updatedInternetGateways = getCrateKubeInternetGateways()
    def updatedRouteTables = getCrateKubeRouteTables()
    def updatedSecurityGroups = getCrateKubeSecurityGroups()

    // Remove existing AWS resources to get only newly created resources
    updatedEc2Instances.removeAll(existingEc2Instances)
    updatedVpcInstances.removeAll(existingVpcInstances)
    updatedSubnets.removeAll(existingSubnets)
    updatedInternetGateways.removeAll(existingInternetGateways)
    updatedRouteTables.removeAll(existingRouteTables)
    updatedSecurityGroups.removeAll(existingSecurityGroups)

    then:
    expect response, notNullValue()
    expect updatedEc2Instances, notNullValue()
    expect updatedEc2Instances.size(), equalTo(2)
    //TODO: There has to be a better way of doing this so
    // that each statement can be viewed individually in an error report
    assert updatedEc2Instances.every {
      it.imageId == 'ami-07ebfd5b3428b6f4d'
      it.instanceType == 't2.micro'
      it.tags.find {it.key == 'Name'}.value().startsWith('cratekube-ec2-instance-')
      it.keyName == awsKeyPairName
    }

    expect updatedVpcInstances.size(), equalTo(1)
    expect updatedVpcInstances[0].cidrBlock, equalTo('10.0.0.0/16')
    expect updatedVpcInstances[0].instanceTenancyAsString(), equalTo('default')

    expect updatedSubnets.size(), equalTo(1)
    expect updatedSubnets[0].cidrBlock, equalTo('10.0.1.0/24')
    expect updatedSubnets[0].vpcId, equalTo(updatedVpcInstances[0].vpcId)
    expect updatedSubnets[0].availabilityZone, equalTo('us-east-1a')
    expect updatedSubnets[0].mapPublicIpOnLaunch, equalTo(true)
    expect updatedSubnets[0].tags.find {it.key == 'Name'}.value(), equalTo('cratekube-subnet-us-east-1')

    expect updatedInternetGateways.size(), equalTo(1)
    expect updatedInternetGateways[0].attachments()[0].vpcId, equalTo(updatedVpcInstances[0].vpcId)
    expect updatedInternetGateways[0].tags.find {it.key == 'Name'}.value(), equalTo('cratekube-igw')

    expect updatedRouteTables.size(), equalTo(1)
    expect updatedRouteTables[0].vpcId, equalTo(updatedVpcInstances[0].vpcId)
    expect updatedRouteTables[0].associations.size(), equalTo(1)
    expect updatedRouteTables[0].associations[0].subnetId, equalTo(updatedSubnets[0].subnetId)
    expect updatedRouteTables[0].associations[0].routeTableId, equalTo(updatedRouteTables[0].routeTableId)

    expect updatedRouteTables[0].routes.size(), equalTo(2)
    def nonLocalRoute = updatedRouteTables[0].routes.find { it.destinationCidrBlock == '0.0.0.0/0' }
    expect nonLocalRoute, notNullValue()
    expect nonLocalRoute.gatewayId, equalTo(updatedInternetGateways[0].internetGatewayId)
    expect updatedRouteTables[0].tags.find {it.key == 'Name'}.value(), equalTo('cratekube-crt')

    expect updatedSecurityGroups.size(), equalTo(1)
    expect updatedSecurityGroups[0].vpcId, equalTo(updatedVpcInstances[0].vpcId)
    expect updatedSecurityGroups[0].ipPermissionsEgress.size(), equalTo(1)
    expect updatedSecurityGroups[0].ipPermissionsEgress[0].ipProtocol, equalTo('-1')
    //expect updatedSecurityGroups[0].ipPermissionsEgress[0].fromPort, equalTo('0') //TODO: Should be 0
    //expect updatedSecurityGroups[0].ipPermissionsEgress[0].toPort, equalTo('0')   //TODO: Should be 0
    expect updatedSecurityGroups[0].ipPermissionsEgress[0].ipRanges.size(), equalTo(1)
    expect updatedSecurityGroups[0].ipPermissionsEgress[0].ipRanges[0].cidrIp, equalTo('0.0.0.0/0')

    expect updatedSecurityGroups[0].ipPermissions().size(), equalTo(1)
    expect updatedSecurityGroups[0].ipPermissions()[0].fromPort, equalTo(22)
    expect updatedSecurityGroups[0].ipPermissions()[0].toPort, equalTo(22)
    expect updatedSecurityGroups[0].ipPermissions()[0].ipProtocol, equalTo('tcp')
    expect updatedSecurityGroups[0].ipPermissions()[0].ipRanges.size(), equalTo(1)
    expect updatedSecurityGroups[0].ipPermissions()[0].ipRanges[0].cidrIp, equalTo('0.0.0.0/0')
  }

  def 'should delete existing CrateKube environment'() {
    given:
    // Get all Resource in AWS prior to environment initialization
    def existingEc2Instances = getCrateKubeEc2Instances()
    def existingVpcInstances = getCrateKubeVpcInstances()
    def existingSubnets = getCrateKubeSubnets()
    def existingInternetGateways = getCrateKubeInternetGateways()
    def existingRouteTables = getCrateKubeRouteTables()
    def existingSecurityGroups = getCrateKubeSecurityGroups()

    when:
    def deleteAttempts = 0
    def envFound = true

    apiRequest(TEST_ENV_NAME).delete()

    do {
      if (deleteAttempts > 0) {
        sleep 10000
      }
      try {
        apiRequest(TEST_ENV_NAME).get(new GenericType<Environment>() {})
      } catch(NotFoundException e){
        envFound = false
      }

      deleteAttempts++
      log.debug "Attempt #{} to retrieve environment being deleted", deleteAttempts
    } while (deleteAttempts < 10 && envFound)

    // Retrieve updated AWS Resources after environment initialization has begun
    def updatedEc2Instances = getCrateKubeEc2Instances()
    def updatedVpcInstances = getCrateKubeVpcInstances()
    def updatedSubnets = getCrateKubeSubnets()
    def updatedInternetGateways = getCrateKubeInternetGateways()
    def updatedRouteTables = getCrateKubeRouteTables()
    def updatedSecurityGroups = getCrateKubeSecurityGroups()

    // Remove existing AWS resources to get only newly created resources
    existingEc2Instances.removeAll(updatedEc2Instances)
    existingVpcInstances.removeAll(updatedVpcInstances)
    existingSubnets.removeAll(updatedSubnets)
    existingInternetGateways.removeAll(updatedInternetGateways)
    existingRouteTables.removeAll(updatedRouteTables)
    existingSecurityGroups.removeAll(updatedSecurityGroups)

    then:
    expect existingEc2Instances.size(), equalTo(2)
    expect existingRouteTables.size(), equalTo(1)
    expect existingVpcInstances.size(), equalTo(1)
    expect existingSubnets.size(), equalTo(1)
    expect existingInternetGateways.size(), equalTo(1)
    expect existingSecurityGroups.size(), equalTo(1)

  }

  def apiRequest(String path = '') {
    return client.target("http://${containerUrl}:${containerPort}/environment/${path}").request()
      .header(HttpHeaders.AUTHORIZATION, TEST_BEARER_TOKEN)
  }

  void deleteExistingTestEnv() {
    def getEnvResponse
    try {
      getEnvResponse = apiRequest(TEST_ENV_NAME).get(new GenericType<Environment>() {})
    } catch (NotFoundException e) {
      log.info("${TEST_ENV_NAME} not found in AWS")
    }

    if(getEnvResponse?.status == APPLIED) {
      log.debug("Removing ${TEST_ENV_NAME} from AWS")
      apiRequest(TEST_ENV_NAME).delete()
    }
  }

  List<Instance> getCrateKubeEc2Instances() {
    def describeCrateKubeInstancesRequest = DescribeInstancesRequest.builder()
      .filters(
        Filter.builder().name('instance-state-name').values('running').build(),
        Filter.builder().name('tag:Name').values('cratekube-ec2-instance-1', 'cratekube-ec2-instance-2').build())
      .build()

    return ec2.describeInstances(describeCrateKubeInstancesRequest).reservations().collect {it.instances[0]}
  }

  List<Vpc> getCrateKubeVpcInstances() {
    def describeCrateKubeVpcRequest = DescribeVpcsRequest.builder()
      .filters(
        Filter.builder().name('state').values('available').build(),
        Filter.builder().name('tag:Name').values('cratekube-vpc').build())
      .build()

    return ec2.describeVpcs(describeCrateKubeVpcRequest).vpcs().collect()
  }

  List<Subnet> getCrateKubeSubnets() {
    return ec2.describeSubnets().subnets().collect()
  }

  List<InternetGateway> getCrateKubeInternetGateways() {
    return ec2.describeInternetGateways().internetGateways().collect()
  }

  List<RouteTable> getCrateKubeRouteTables() {
    def describeCrateKubeRouteTables = DescribeRouteTablesRequest.builder()
      .filters(Filter.builder().name('tag:Name').values('cratekube-crt').build())
      .build()

    return ec2.describeRouteTables(describeCrateKubeRouteTables).routeTables().collect()
  }

  List<SecurityGroup> getCrateKubeSecurityGroups() {
    def describeCrateKubeSecurityGroups= DescribeSecurityGroupsRequest.builder()
      .filters(Filter.builder().name('tag:Name').values('cratekube-ssh-sg').build())
      .build()

    return ec2.describeSecurityGroups(describeCrateKubeSecurityGroups).securityGroups().collect()
  }

}
