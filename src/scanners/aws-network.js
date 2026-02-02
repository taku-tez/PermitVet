/**
 * AWS Network Security Scanner
 * VPC, Security Groups, NACLs, Flow Logs, Transit Gateway
 */

/**
 * Scan AWS network security configuration
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanAWSNetwork(options = {}) {
  const findings = [];

  try {
    const { EC2Client } = require('@aws-sdk/client-ec2');
    const config = options.profile ? { profile: options.profile } : {};
    const client = new EC2Client(config);

    // 1. VPC Configuration
    console.log('  Scanning VPCs...');
    const vpcFindings = await scanVPCs(client);
    findings.push(...vpcFindings);

    // 2. Security Groups
    console.log('  Scanning Security Groups...');
    const sgFindings = await scanSecurityGroups(client);
    findings.push(...sgFindings);

    // 3. Network ACLs
    console.log('  Scanning Network ACLs...');
    const naclFindings = await scanNetworkACLs(client);
    findings.push(...naclFindings);

    // 4. VPC Flow Logs
    console.log('  Scanning VPC Flow Logs...');
    const flowLogFindings = await scanFlowLogs(client);
    findings.push(...flowLogFindings);

    // 5. VPC Endpoints
    console.log('  Scanning VPC Endpoints...');
    const endpointFindings = await scanVPCEndpoints(client);
    findings.push(...endpointFindings);

    // 6. Internet Gateways
    console.log('  Scanning Internet Gateways...');
    const igwFindings = await scanInternetGateways(client);
    findings.push(...igwFindings);

  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('AWS SDK not installed.');
    } else if (error.name === 'CredentialsProviderError') {
      // Skip if no credentials
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan VPCs for security issues
 */
async function scanVPCs(client) {
  const findings = [];
  
  try {
    const { DescribeVpcsCommand } = require('@aws-sdk/client-ec2');
    
    const response = await client.send(new DescribeVpcsCommand({}));
    
    for (const vpc of response.Vpcs || []) {
      const vpcName = vpc.Tags?.find(t => t.Key === 'Name')?.Value || vpc.VpcId;
      
      // Check if default VPC
      if (vpc.IsDefault) {
        findings.push({
          id: 'aws-default-vpc-in-use',
          severity: 'info',
          resource: `VPC/${vpcName}`,
          message: 'Default VPC exists in this region',
          recommendation: 'Consider removing or not using the default VPC',
          cis: '5.4',
        });
      }
      
      // Check for DNS settings
      const { DescribeVpcAttributeCommand } = require('@aws-sdk/client-ec2');
      
      const dnsSupport = await client.send(new DescribeVpcAttributeCommand({
        VpcId: vpc.VpcId,
        Attribute: 'enableDnsSupport',
      }));
      
      const dnsHostnames = await client.send(new DescribeVpcAttributeCommand({
        VpcId: vpc.VpcId,
        Attribute: 'enableDnsHostnames',
      }));
      
      if (!dnsSupport.EnableDnsSupport?.Value || !dnsHostnames.EnableDnsHostnames?.Value) {
        findings.push({
          id: 'aws-vpc-dns-disabled',
          severity: 'info',
          resource: `VPC/${vpcName}`,
          message: 'VPC does not have DNS support and hostnames fully enabled',
          recommendation: 'Enable DNS support for VPC endpoints and private hosted zones',
        });
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan Security Groups for security issues
 */
async function scanSecurityGroups(client) {
  const findings = [];
  
  // Dangerous ports to check
  const dangerousPorts = [
    { port: 22, name: 'SSH' },
    { port: 3389, name: 'RDP' },
    { port: 3306, name: 'MySQL' },
    { port: 5432, name: 'PostgreSQL' },
    { port: 1433, name: 'MSSQL' },
    { port: 27017, name: 'MongoDB' },
    { port: 6379, name: 'Redis' },
    { port: 9200, name: 'Elasticsearch' },
    { port: 11211, name: 'Memcached' },
    { port: 23, name: 'Telnet' },
    { port: 21, name: 'FTP' },
    { port: 445, name: 'SMB' },
    { port: 135, name: 'MSRPC' },
  ];
  
  try {
    const { DescribeSecurityGroupsCommand, DescribeSecurityGroupRulesCommand } = require('@aws-sdk/client-ec2');
    
    const response = await client.send(new DescribeSecurityGroupsCommand({}));
    
    for (const sg of response.SecurityGroups || []) {
      const sgName = sg.GroupName;
      const sgId = sg.GroupId;
      
      // Check default security group
      if (sgName === 'default') {
        const hasInboundRules = sg.IpPermissions?.some(r => 
          r.IpRanges?.length > 0 || r.Ipv6Ranges?.length > 0 || r.UserIdGroupPairs?.length > 0
        );
        
        if (hasInboundRules) {
          findings.push({
            id: 'aws-default-sg-has-rules',
            severity: 'warning',
            resource: `SecurityGroup/${sgId}`,
            message: 'Default security group has non-default inbound rules',
            recommendation: 'Remove rules from default security group',
            cis: '5.3',
          });
        }
      }
      
      // Check inbound rules
      for (const rule of sg.IpPermissions || []) {
        const hasPublicAccess = rule.IpRanges?.some(r => r.CidrIp === '0.0.0.0/0') ||
                               rule.Ipv6Ranges?.some(r => r.CidrIpv6 === '::/0');
        
        if (!hasPublicAccess) continue;
        
        // Check for all traffic
        if (rule.IpProtocol === '-1') {
          findings.push({
            id: 'aws-sg-public-all-traffic',
            severity: 'critical',
            resource: `SecurityGroup/${sgId}`,
            message: `Security group ${sgName} allows ALL traffic from the internet`,
            recommendation: 'Restrict to specific ports and protocols',
          });
          continue;
        }
        
        // Check for all ports
        if (rule.FromPort === 0 && rule.ToPort === 65535) {
          findings.push({
            id: 'aws-sg-public-all-ports',
            severity: 'critical',
            resource: `SecurityGroup/${sgId}`,
            message: `Security group ${sgName} allows all ${rule.IpProtocol} ports from the internet`,
            recommendation: 'Restrict to specific required ports',
          });
          continue;
        }
        
        // Check for dangerous ports
        for (const dp of dangerousPorts) {
          if ((rule.FromPort <= dp.port && rule.ToPort >= dp.port) ||
              (rule.FromPort === -1 && rule.ToPort === -1)) {
            findings.push({
              id: `aws-sg-public-${dp.name.toLowerCase()}`,
              severity: dp.port === 22 || dp.port === 3389 ? 'warning' : 'critical',
              resource: `SecurityGroup/${sgId}`,
              message: `Security group ${sgName} allows ${dp.name} (port ${dp.port}) from the internet`,
              recommendation: `Restrict ${dp.name} access to specific IP ranges`,
              cis: dp.port === 22 || dp.port === 3389 ? '5.2' : undefined,
            });
          }
        }
      }
      
      // Check outbound rules for unrestricted egress
      const hasUnrestrictedEgress = sg.IpPermissionsEgress?.some(r => 
        r.IpProtocol === '-1' && 
        r.IpRanges?.some(ip => ip.CidrIp === '0.0.0.0/0')
      );
      
      if (hasUnrestrictedEgress) {
        findings.push({
          id: 'aws-sg-unrestricted-egress',
          severity: 'info',
          resource: `SecurityGroup/${sgId}`,
          message: `Security group ${sgName} allows unrestricted outbound traffic`,
          recommendation: 'Consider restricting egress to required destinations',
        });
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan Network ACLs for security issues
 */
async function scanNetworkACLs(client) {
  const findings = [];
  
  try {
    const { DescribeNetworkAclsCommand } = require('@aws-sdk/client-ec2');
    
    const response = await client.send(new DescribeNetworkAclsCommand({}));
    
    for (const nacl of response.NetworkAcls || []) {
      const naclName = nacl.Tags?.find(t => t.Key === 'Name')?.Value || nacl.NetworkAclId;
      
      for (const entry of nacl.Entries || []) {
        if (entry.Egress) continue; // Focus on ingress
        if (entry.RuleAction !== 'allow') continue;
        
        const isPublic = entry.CidrBlock === '0.0.0.0/0' || entry.Ipv6CidrBlock === '::/0';
        if (!isPublic) continue;
        
        // Check for all traffic
        if (entry.Protocol === '-1') {
          findings.push({
            id: 'aws-nacl-public-all-traffic',
            severity: 'warning',
            resource: `NACL/${naclName}`,
            message: `NACL allows all traffic from the internet (rule ${entry.RuleNumber})`,
            recommendation: 'Restrict NACL rules to specific protocols and ports',
          });
        }
        
        // Check for admin ports
        if (entry.PortRange) {
          const adminPorts = [22, 3389];
          for (const port of adminPorts) {
            if (port >= entry.PortRange.From && port <= entry.PortRange.To) {
              findings.push({
                id: 'aws-nacl-public-admin',
                severity: 'warning',
                resource: `NACL/${naclName}`,
                message: `NACL allows public access to admin port ${port} (rule ${entry.RuleNumber})`,
                recommendation: 'Restrict admin port access at NACL level',
                cis: '5.1',
              });
            }
          }
        }
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan VPC Flow Logs
 */
async function scanFlowLogs(client) {
  const findings = [];
  
  try {
    const { DescribeVpcsCommand, DescribeFlowLogsCommand } = require('@aws-sdk/client-ec2');
    
    // Get all VPCs
    const vpcsResponse = await client.send(new DescribeVpcsCommand({}));
    const vpcIds = vpcsResponse.Vpcs?.map(v => v.VpcId) || [];
    
    // Get all flow logs
    const flowLogsResponse = await client.send(new DescribeFlowLogsCommand({}));
    const flowLogs = flowLogsResponse.FlowLogs || [];
    
    // Check each VPC has flow logs
    for (const vpcId of vpcIds) {
      const vpcName = vpcsResponse.Vpcs.find(v => v.VpcId === vpcId)?.Tags?.find(t => t.Key === 'Name')?.Value || vpcId;
      
      const hasFlowLog = flowLogs.some(fl => 
        fl.ResourceId === vpcId && fl.FlowLogStatus === 'ACTIVE'
      );
      
      if (!hasFlowLog) {
        findings.push({
          id: 'aws-vpc-no-flow-logs',
          severity: 'warning',
          resource: `VPC/${vpcName}`,
          message: 'VPC does not have flow logs enabled',
          recommendation: 'Enable VPC flow logs for network traffic analysis',
          cis: '3.9',
        });
      }
    }
    
    // Check flow log configuration
    for (const fl of flowLogs) {
      if (fl.FlowLogStatus !== 'ACTIVE') {
        findings.push({
          id: 'aws-flow-log-not-active',
          severity: 'warning',
          resource: `FlowLog/${fl.FlowLogId}`,
          message: `Flow log is in ${fl.FlowLogStatus} status`,
          recommendation: 'Investigate and fix flow log issues',
        });
      }
      
      // Check log destination
      if (!fl.LogDestination && !fl.LogGroupName) {
        findings.push({
          id: 'aws-flow-log-no-destination',
          severity: 'warning',
          resource: `FlowLog/${fl.FlowLogId}`,
          message: 'Flow log has no destination configured',
          recommendation: 'Configure CloudWatch Logs or S3 as destination',
        });
      }
      
      // Check traffic type
      if (fl.TrafficType === 'ACCEPT') {
        findings.push({
          id: 'aws-flow-log-accept-only',
          severity: 'info',
          resource: `FlowLog/${fl.FlowLogId}`,
          message: 'Flow log only captures accepted traffic',
          recommendation: 'Consider capturing ALL or REJECT traffic for security analysis',
        });
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan VPC Endpoints for security issues
 */
async function scanVPCEndpoints(client) {
  const findings = [];
  
  try {
    const { DescribeVpcEndpointsCommand } = require('@aws-sdk/client-ec2');
    
    const response = await client.send(new DescribeVpcEndpointsCommand({}));
    
    for (const endpoint of response.VpcEndpoints || []) {
      const endpointName = endpoint.Tags?.find(t => t.Key === 'Name')?.Value || endpoint.VpcEndpointId;
      
      // Check endpoint policy
      if (endpoint.PolicyDocument) {
        const policy = JSON.parse(endpoint.PolicyDocument);
        
        for (const statement of policy.Statement || []) {
          if (statement.Principal === '*' && statement.Effect === 'Allow') {
            if (!statement.Condition) {
              findings.push({
                id: 'aws-vpce-public-policy',
                severity: 'warning',
                resource: `VPCEndpoint/${endpointName}`,
                message: 'VPC endpoint policy allows any principal without conditions',
                recommendation: 'Restrict endpoint policy to specific principals or add conditions',
              });
            }
          }
        }
      }
      
      // Check for interface endpoints without private DNS
      if (endpoint.VpcEndpointType === 'Interface' && !endpoint.PrivateDnsEnabled) {
        findings.push({
          id: 'aws-vpce-no-private-dns',
          severity: 'info',
          resource: `VPCEndpoint/${endpointName}`,
          message: 'Interface VPC endpoint does not have private DNS enabled',
          recommendation: 'Enable private DNS for seamless integration',
        });
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan Internet Gateways for security issues
 */
async function scanInternetGateways(client) {
  const findings = [];
  
  try {
    const { DescribeInternetGatewaysCommand, DescribeRouteTablesCommand } = require('@aws-sdk/client-ec2');
    
    const igwResponse = await client.send(new DescribeInternetGatewaysCommand({}));
    const rtResponse = await client.send(new DescribeRouteTablesCommand({}));
    
    for (const igw of igwResponse.InternetGateways || []) {
      const igwName = igw.Tags?.find(t => t.Key === 'Name')?.Value || igw.InternetGatewayId;
      
      // Check if attached to a VPC
      if (!igw.Attachments || igw.Attachments.length === 0) {
        findings.push({
          id: 'aws-igw-unattached',
          severity: 'info',
          resource: `IGW/${igwName}`,
          message: 'Internet Gateway is not attached to any VPC',
          recommendation: 'Remove unused Internet Gateways',
        });
        continue;
      }
      
      // Check for subnets with direct internet routes
      const vpcId = igw.Attachments[0].VpcId;
      const routeTables = rtResponse.RouteTables?.filter(rt => rt.VpcId === vpcId) || [];
      
      for (const rt of routeTables) {
        const hasInternetRoute = rt.Routes?.some(r => 
          r.GatewayId === igw.InternetGatewayId && r.DestinationCidrBlock === '0.0.0.0/0'
        );
        
        if (hasInternetRoute) {
          // Check associated subnets
          const isMain = rt.Associations?.some(a => a.Main);
          
          if (isMain) {
            findings.push({
              id: 'aws-main-rt-has-igw',
              severity: 'info',
              resource: `RouteTable/${rt.RouteTableId}`,
              message: 'Main route table has internet gateway route',
              recommendation: 'Use explicit route table associations instead of main route table for internet access',
            });
          }
        }
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

module.exports = { scanAWSNetwork };
