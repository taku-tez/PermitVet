/**
 * CIS Benchmark Controls Module
 * Comprehensive CIS AWS/Azure/GCP Foundations Benchmark checks
 */

// Types imported as needed

/** CIS Control check result */
export interface CISCheckResult {
  status: 'PASS' | 'FAIL' | 'INFO';
  message: string;
  details?: string[];
}

/** CIS Control definition */
export interface CISControl {
  id: string;
  control: string;
  title: string;
  check: (client: unknown, resource?: string) => Promise<CISCheckResult>;
}

/** CIS Controls by provider */
export interface CISControlsMap {
  aws: CISControl[];
  azure?: CISControl[];
  gcp?: CISControl[];
}

/**
 * CIS AWS Foundations Benchmark v3.0 Controls
 * Controls not yet implemented in main scanner
 */
export const CIS_AWS_V3_CONTROLS: CISControl[] = [
  // 1.x Identity and Access Management
  {
    id: 'cis-aws-1.17',
    control: '1.17',
    title: 'Ensure a support role has been created to manage incidents with AWS Support',
    check: async (client: unknown): Promise<CISCheckResult> => {
      // Check for AWSSupportAccess policy attachment
      const { ListPoliciesCommand, ListEntitiesForPolicyCommand } =
        await import('@aws-sdk/client-iam');

      const iamClient = client as {
        send: (cmd: unknown) => Promise<{
          Policies?: Array<{ PolicyName?: string; Arn?: string }>;
          PolicyUsers?: unknown[];
          PolicyGroups?: unknown[];
          PolicyRoles?: unknown[];
        }>;
      };

      const policiesResponse = await iamClient.send(
        new ListPoliciesCommand({
          Scope: 'AWS',
          OnlyAttached: true,
        })
      );

      const supportPolicy = policiesResponse.Policies?.find(
        p => p.PolicyName === 'AWSSupportAccess'
      );

      if (!supportPolicy) {
        return {
          status: 'FAIL',
          message: 'AWSSupportAccess policy is not attached to any entity',
        };
      }

      const entities = await iamClient.send(
        new ListEntitiesForPolicyCommand({
          PolicyArn: supportPolicy.Arn,
        })
      );

      const hasEntities =
        (entities.PolicyUsers?.length || 0) +
          (entities.PolicyGroups?.length || 0) +
          (entities.PolicyRoles?.length || 0) >
        0;

      return {
        status: hasEntities ? 'PASS' : 'FAIL',
        message: hasEntities ? 'Support role configured' : 'No entities with AWSSupportAccess',
      };
    },
  },
  {
    id: 'cis-aws-1.19',
    control: '1.19',
    title: 'Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { ListServerCertificatesCommand } = await import('@aws-sdk/client-iam');

      const iamClient = client as {
        send: (cmd: unknown) => Promise<{
          ServerCertificateMetadataList?: Array<{
            ServerCertificateName?: string;
            Expiration?: Date | string;
          }>;
        }>;
      };

      const response = await iamClient.send(new ListServerCertificatesCommand({}));
      const now = new Date();

      const expired =
        response.ServerCertificateMetadataList?.filter(
          cert => new Date(cert.Expiration as string) < now
        ) || [];

      return {
        status: expired.length === 0 ? 'PASS' : 'FAIL',
        message:
          expired.length === 0
            ? 'No expired certificates'
            : `${expired.length} expired certificate(s) found`,
        details: expired.map(c => c.ServerCertificateName || ''),
      };
    },
  },

  // 2.x Storage
  {
    id: 'cis-aws-2.1.1',
    control: '2.1.1',
    title: 'Ensure S3 Bucket Policy is set to deny HTTP requests',
    check: async (client: unknown, bucketName?: string): Promise<CISCheckResult> => {
      const { GetBucketPolicyCommand } = await import('@aws-sdk/client-s3');

      const s3Client = client as {
        send: (cmd: unknown) => Promise<{ Policy?: string }>;
      };

      try {
        const response = await s3Client.send(
          new GetBucketPolicyCommand({
            Bucket: bucketName,
          })
        );

        interface PolicyStatement {
          Effect?: string;
          Condition?: {
            Bool?: { 'aws:SecureTransport'?: string };
          };
        }

        const policy = JSON.parse(response.Policy || '{}') as { Statement?: PolicyStatement[] };
        const hasDenyHttp = policy.Statement?.some(
          s => s.Effect === 'Deny' && s.Condition?.Bool?.['aws:SecureTransport'] === 'false'
        );

        return {
          status: hasDenyHttp ? 'PASS' : 'FAIL',
          message: hasDenyHttp ? 'HTTP requests denied' : 'No policy denying HTTP requests',
        };
      } catch (e) {
        const err = e as Error & { name?: string };
        if (err.name === 'NoSuchBucketPolicy') {
          return {
            status: 'FAIL',
            message: 'No bucket policy configured',
          };
        }
        throw e;
      }
    },
  },
  {
    id: 'cis-aws-2.1.2',
    control: '2.1.2',
    title: 'Ensure MFA Delete is enabled on S3 buckets',
    check: async (client: unknown, bucketName?: string): Promise<CISCheckResult> => {
      const { GetBucketVersioningCommand } = await import('@aws-sdk/client-s3');

      const s3Client = client as {
        send: (cmd: unknown) => Promise<{ MFADelete?: string }>;
      };

      const response = await s3Client.send(
        new GetBucketVersioningCommand({
          Bucket: bucketName,
        })
      );

      const mfaDelete = response.MFADelete === 'Enabled';

      return {
        status: mfaDelete ? 'PASS' : 'FAIL',
        message: mfaDelete ? 'MFA Delete enabled' : 'MFA Delete not enabled',
      };
    },
  },
  {
    id: 'cis-aws-2.1.5',
    control: '2.1.5',
    title: 'Ensure S3 buckets are configured with Object Lock',
    check: async (client: unknown, bucketName?: string): Promise<CISCheckResult> => {
      const { GetObjectLockConfigurationCommand } = await import('@aws-sdk/client-s3');

      const s3Client = client as {
        send: (cmd: unknown) => Promise<{
          ObjectLockConfiguration?: { ObjectLockEnabled?: string };
        }>;
      };

      try {
        const response = await s3Client.send(
          new GetObjectLockConfigurationCommand({
            Bucket: bucketName,
          })
        );

        const enabled = response.ObjectLockConfiguration?.ObjectLockEnabled === 'Enabled';

        return {
          status: enabled ? 'PASS' : 'INFO',
          message: enabled ? 'Object Lock enabled' : 'Object Lock not enabled',
        };
      } catch {
        return {
          status: 'INFO',
          message: 'Object Lock not configured',
        };
      }
    },
  },

  // 2.2.x EBS
  {
    id: 'cis-aws-2.2.1',
    control: '2.2.1',
    title: 'Ensure EBS Volume Encryption is Enabled in all Regions',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { GetEbsEncryptionByDefaultCommand } = await import('@aws-sdk/client-ec2');

      const ec2Client = client as {
        send: (cmd: unknown) => Promise<{ EbsEncryptionByDefault?: boolean }>;
      };

      const response = await ec2Client.send(new GetEbsEncryptionByDefaultCommand({}));

      return {
        status: response.EbsEncryptionByDefault ? 'PASS' : 'FAIL',
        message: response.EbsEncryptionByDefault
          ? 'EBS encryption by default enabled'
          : 'EBS encryption by default not enabled',
      };
    },
  },

  // 2.3.x RDS
  {
    id: 'cis-aws-2.3.1',
    control: '2.3.1',
    title: 'Ensure RDS instances are not publicly accessible',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeDBInstancesCommand } = await import('@aws-sdk/client-rds');

      const rdsClient = client as {
        send: (cmd: unknown) => Promise<{
          DBInstances?: Array<{ PubliclyAccessible?: boolean; DBInstanceIdentifier?: string }>;
        }>;
      };

      const response = await rdsClient.send(new DescribeDBInstancesCommand({}));
      const publicInstances = response.DBInstances?.filter(db => db.PubliclyAccessible) || [];

      return {
        status: publicInstances.length === 0 ? 'PASS' : 'FAIL',
        message:
          publicInstances.length === 0
            ? 'No publicly accessible RDS instances'
            : `${publicInstances.length} publicly accessible RDS instance(s)`,
        details: publicInstances.map(db => db.DBInstanceIdentifier || ''),
      };
    },
  },
  {
    id: 'cis-aws-2.3.2',
    control: '2.3.2',
    title: 'Ensure Auto Minor Version Upgrade is enabled for RDS instances',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeDBInstancesCommand } = await import('@aws-sdk/client-rds');

      const rdsClient = client as {
        send: (cmd: unknown) => Promise<{
          DBInstances?: Array<{
            AutoMinorVersionUpgrade?: boolean;
            DBInstanceIdentifier?: string;
          }>;
        }>;
      };

      const response = await rdsClient.send(new DescribeDBInstancesCommand({}));
      const noAutoUpgrade = response.DBInstances?.filter(db => !db.AutoMinorVersionUpgrade) || [];

      return {
        status: noAutoUpgrade.length === 0 ? 'PASS' : 'FAIL',
        message:
          noAutoUpgrade.length === 0
            ? 'All RDS instances have auto minor version upgrade enabled'
            : `${noAutoUpgrade.length} RDS instance(s) without auto upgrade`,
        details: noAutoUpgrade.map(db => db.DBInstanceIdentifier || ''),
      };
    },
  },

  // 3.x Logging
  {
    id: 'cis-aws-3.1',
    control: '3.1',
    title: 'Ensure CloudTrail is enabled in all regions',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeTrailsCommand, GetTrailStatusCommand } =
        await import('@aws-sdk/client-cloudtrail');

      const cloudtrailClient = client as {
        send: (cmd: unknown) => Promise<{
          trailList?: Array<{ IsMultiRegionTrail?: boolean; Name?: string }>;
          IsLogging?: boolean;
        }>;
      };

      const response = await cloudtrailClient.send(new DescribeTrailsCommand({}));
      const multiRegionTrails = response.trailList?.filter(t => t.IsMultiRegionTrail) || [];

      if (multiRegionTrails.length === 0) {
        return {
          status: 'FAIL',
          message: 'No multi-region CloudTrail found',
        };
      }

      // Check if at least one is logging
      for (const trail of multiRegionTrails) {
        const status = await cloudtrailClient.send(
          new GetTrailStatusCommand({
            Name: trail.Name,
          })
        );

        if (status.IsLogging) {
          return {
            status: 'PASS',
            message: `Multi-region CloudTrail '${trail.Name}' is logging`,
          };
        }
      }

      return {
        status: 'FAIL',
        message: 'Multi-region CloudTrail exists but is not logging',
      };
    },
  },
  {
    id: 'cis-aws-3.2',
    control: '3.2',
    title: 'Ensure CloudTrail log file validation is enabled',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeTrailsCommand } = await import('@aws-sdk/client-cloudtrail');

      const cloudtrailClient = client as {
        send: (cmd: unknown) => Promise<{
          trailList?: Array<{ LogFileValidationEnabled?: boolean; Name?: string }>;
        }>;
      };

      const response = await cloudtrailClient.send(new DescribeTrailsCommand({}));
      const noValidation = response.trailList?.filter(t => !t.LogFileValidationEnabled) || [];

      return {
        status: noValidation.length === 0 ? 'PASS' : 'FAIL',
        message:
          noValidation.length === 0
            ? 'All trails have log file validation enabled'
            : `${noValidation.length} trail(s) without log file validation`,
        details: noValidation.map(t => t.Name || ''),
      };
    },
  },
  {
    id: 'cis-aws-3.4',
    control: '3.4',
    title: 'Ensure CloudTrail trails are integrated with CloudWatch Logs',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeTrailsCommand } = await import('@aws-sdk/client-cloudtrail');

      const cloudtrailClient = client as {
        send: (cmd: unknown) => Promise<{
          trailList?: Array<{ CloudWatchLogsLogGroupArn?: string; Name?: string }>;
        }>;
      };

      const response = await cloudtrailClient.send(new DescribeTrailsCommand({}));
      const noCloudWatch = response.trailList?.filter(t => !t.CloudWatchLogsLogGroupArn) || [];

      return {
        status: noCloudWatch.length === 0 ? 'PASS' : 'FAIL',
        message:
          noCloudWatch.length === 0
            ? 'All trails integrated with CloudWatch Logs'
            : `${noCloudWatch.length} trail(s) not integrated with CloudWatch Logs`,
        details: noCloudWatch.map(t => t.Name || ''),
      };
    },
  },
  {
    id: 'cis-aws-3.7',
    control: '3.7',
    title: 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeTrailsCommand } = await import('@aws-sdk/client-cloudtrail');

      const cloudtrailClient = client as {
        send: (cmd: unknown) => Promise<{
          trailList?: Array<{ KMSKeyId?: string; Name?: string }>;
        }>;
      };

      const response = await cloudtrailClient.send(new DescribeTrailsCommand({}));
      const noKms = response.trailList?.filter(t => !t.KMSKeyId) || [];

      return {
        status: noKms.length === 0 ? 'PASS' : 'FAIL',
        message:
          noKms.length === 0
            ? 'All trails encrypted with KMS'
            : `${noKms.length} trail(s) not encrypted with KMS`,
        details: noKms.map(t => t.Name || ''),
      };
    },
  },

  // 4.x Monitoring
  {
    id: 'cis-aws-4.1',
    control: '4.1',
    title: 'Ensure unauthorized API calls are monitored',
    // This requires CloudWatch Logs Metric Filter analysis
    check: async (client: unknown, logGroupName?: string): Promise<CISCheckResult> => {
      const { DescribeMetricFiltersCommand } = await import('@aws-sdk/client-cloudwatch-logs');

      const cwlClient = client as {
        send: (cmd: unknown) => Promise<{
          metricFilters?: Array<{ filterPattern?: string }>;
        }>;
      };

      const response = await cwlClient.send(
        new DescribeMetricFiltersCommand({
          logGroupName,
        })
      );

      // Check for metric filter pattern matching unauthorized API calls
      const hasFilter = response.metricFilters?.some(
        f =>
          f.filterPattern?.includes('UnauthorizedAccess') ||
          f.filterPattern?.includes('AccessDenied') ||
          f.filterPattern?.includes('errorCode')
      );

      return {
        status: hasFilter ? 'PASS' : 'INFO',
        message: hasFilter
          ? 'Unauthorized API call monitoring configured'
          : 'No metric filter for unauthorized API calls detected',
      };
    },
  },

  // 5.x Networking
  {
    id: 'cis-aws-5.1',
    control: '5.1',
    title: 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeNetworkAclsCommand } = await import('@aws-sdk/client-ec2');

      interface NaclEntry {
        Egress?: boolean;
        RuleAction?: string;
        CidrBlock?: string;
        Ipv6CidrBlock?: string;
        PortRange?: { From?: number; To?: number };
        RuleNumber?: number;
      }

      interface Nacl {
        NetworkAclId?: string;
        Entries?: NaclEntry[];
      }

      const ec2Client = client as {
        send: (cmd: unknown) => Promise<{ NetworkAcls?: Nacl[] }>;
      };

      const response = await ec2Client.send(new DescribeNetworkAclsCommand({}));
      const adminPorts = [22, 3389]; // SSH, RDP

      const violations: Array<{ naclId?: string; ruleNumber?: number; port: number }> = [];

      for (const nacl of response.NetworkAcls || []) {
        for (const entry of nacl.Entries || []) {
          if (entry.Egress) continue; // Only check ingress
          if (entry.RuleAction !== 'allow') continue;
          if (entry.CidrBlock !== '0.0.0.0/0' && entry.Ipv6CidrBlock !== '::/0') continue;

          // Check port range
          if (entry.PortRange) {
            for (const port of adminPorts) {
              if (port >= (entry.PortRange.From || 0) && port <= (entry.PortRange.To || 0)) {
                violations.push({
                  naclId: nacl.NetworkAclId,
                  ruleNumber: entry.RuleNumber,
                  port,
                });
              }
            }
          }
        }
      }

      return {
        status: violations.length === 0 ? 'PASS' : 'FAIL',
        message:
          violations.length === 0
            ? 'No NACLs allow public access to admin ports'
            : `${violations.length} NACL rule(s) allow public admin access`,
        details: violations.map(v => `NACL ${v.naclId} rule ${v.ruleNumber} port ${v.port}`),
      };
    },
  },
  {
    id: 'cis-aws-5.2',
    control: '5.2',
    title: 'Ensure no Security Groups allow ingress from 0.0.0.0/0 to remote admin ports',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeSecurityGroupsCommand } = await import('@aws-sdk/client-ec2');

      interface IpPermission {
        IpRanges?: Array<{ CidrIp?: string }>;
        Ipv6Ranges?: Array<{ CidrIpv6?: string }>;
        FromPort?: number;
        ToPort?: number;
      }

      interface SecurityGroup {
        GroupId?: string;
        GroupName?: string;
        IpPermissions?: IpPermission[];
      }

      const ec2Client = client as {
        send: (cmd: unknown) => Promise<{ SecurityGroups?: SecurityGroup[] }>;
      };

      const response = await ec2Client.send(new DescribeSecurityGroupsCommand({}));
      const adminPorts = [22, 3389]; // SSH, RDP

      const violations: Array<{ sgId?: string; sgName?: string; port: number }> = [];

      for (const sg of response.SecurityGroups || []) {
        for (const rule of sg.IpPermissions || []) {
          const hasPublicAccess =
            rule.IpRanges?.some(r => r.CidrIp === '0.0.0.0/0') ||
            rule.Ipv6Ranges?.some(r => r.CidrIpv6 === '::/0');

          if (!hasPublicAccess) continue;

          for (const port of adminPorts) {
            const fromPort = rule.FromPort ?? 0;
            const toPort = rule.ToPort ?? 0;
            if ((fromPort <= port && toPort >= port) || (fromPort === -1 && toPort === -1)) {
              violations.push({
                sgId: sg.GroupId,
                sgName: sg.GroupName,
                port,
              });
            }
          }
        }
      }

      return {
        status: violations.length === 0 ? 'PASS' : 'FAIL',
        message:
          violations.length === 0
            ? 'No SGs allow public access to admin ports'
            : `${violations.length} SG rule(s) allow public admin access`,
        details: violations.map(v => `SG ${v.sgId} (${v.sgName}) port ${v.port}`),
      };
    },
  },
  {
    id: 'cis-aws-5.3',
    control: '5.3',
    title: 'Ensure the default security group restricts all traffic',
    check: async (client: unknown): Promise<CISCheckResult> => {
      const { DescribeSecurityGroupsCommand } = await import('@aws-sdk/client-ec2');

      interface IpPermission {
        IpRanges?: Array<{ CidrIp?: string }>;
        Ipv6Ranges?: Array<{ CidrIpv6?: string }>;
      }

      interface SecurityGroup {
        GroupId?: string;
        VpcId?: string;
        IpPermissions?: IpPermission[];
        IpPermissionsEgress?: IpPermission[];
      }

      const ec2Client = client as {
        send: (cmd: unknown) => Promise<{ SecurityGroups?: SecurityGroup[] }>;
      };

      const response = await ec2Client.send(
        new DescribeSecurityGroupsCommand({
          Filters: [{ Name: 'group-name', Values: ['default'] }],
        })
      );

      const violations: Array<{ sgId?: string; vpcId?: string }> = [];

      for (const sg of response.SecurityGroups || []) {
        if ((sg.IpPermissions?.length ?? 0) > 0 || (sg.IpPermissionsEgress?.length ?? 0) > 0) {
          // Check if only self-referencing rules exist
          const hasExternalRules =
            sg.IpPermissions?.some(
              r => (r.IpRanges?.length ?? 0) > 0 || (r.Ipv6Ranges?.length ?? 0) > 0
            ) ||
            sg.IpPermissionsEgress?.some(
              r => (r.IpRanges?.length ?? 0) > 0 || (r.Ipv6Ranges?.length ?? 0) > 0
            );

          if (hasExternalRules) {
            violations.push({
              sgId: sg.GroupId,
              vpcId: sg.VpcId,
            });
          }
        }
      }

      return {
        status: violations.length === 0 ? 'PASS' : 'FAIL',
        message:
          violations.length === 0
            ? 'All default SGs restrict traffic'
            : `${violations.length} default SG(s) have permissive rules`,
        details: violations.map(v => `SG ${v.sgId} in VPC ${v.vpcId}`),
      };
    },
  },
];

/**
 * Get all CIS controls
 */
export function getAllCISControls(): CISControlsMap {
  return {
    aws: CIS_AWS_V3_CONTROLS,
    // azure and gcp controls can be added here
  };
}

/**
 * Get CIS control by ID
 */
export function getCISControl(
  provider: keyof CISControlsMap,
  controlId: string
): CISControl | undefined {
  const controls = getAllCISControls()[provider] || [];
  return controls.find(c => c.control === controlId || c.id === controlId);
}
