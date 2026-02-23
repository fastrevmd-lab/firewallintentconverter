/**
 * Sample Configurations for Testing
 *
 * PAN-OS samples:
 *   1. Basic — Small office: 2 zones, 5 address objects, 6 security rules, 1 NAT
 *   2. Medium — Branch office: 3 zones, address groups, service objects, 12 rules, 3 NAT
 *   3. Complex — Enterprise: 4 zones, custom apps, security profiles, disabled rules, 20+ rules
 *   4. Edge Cases — Tricky constructs: FQDN, any/any, tags, application-default, dynamic groups
 *
 * SRX samples:
 *   5. SRX Basic — SRX set commands: 3 zones, address objects, 6 security policies, source NAT
 */

export const SAMPLE_CONFIGS = {

  // =========================================================================
  // SAMPLE 1: Basic Small Office
  // =========================================================================
  basic: {
    vendor: 'panos',
    label: 'Basic (6 rules)',
    description: 'Small office: 2 zones, 5 address objects, 6 security rules, 1 source NAT',
    xml: `<?xml version="1.0"?>
<config version="10.1.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust">
              <network>
                <layer3>
                  <member>ethernet1/1</member>
                </layer3>
              </network>
            </entry>
            <entry name="untrust">
              <network>
                <layer3>
                  <member>ethernet1/2</member>
                </layer3>
              </network>
            </entry>
          </zone>
          <address>
            <entry name="web-server-1">
              <ip-netmask>10.1.1.10/32</ip-netmask>
              <description>Primary web server</description>
            </entry>
            <entry name="web-server-2">
              <ip-netmask>10.1.1.11/32</ip-netmask>
              <description>Secondary web server</description>
            </entry>
            <entry name="db-server">
              <ip-netmask>10.1.2.20/32</ip-netmask>
              <description>PostgreSQL database</description>
            </entry>
            <entry name="internal-net">
              <ip-netmask>10.1.0.0/16</ip-netmask>
              <description>Internal network</description>
            </entry>
            <entry name="dns-server">
              <ip-netmask>10.1.1.5/32</ip-netmask>
              <description>Internal DNS resolver</description>
            </entry>
          </address>
          <service>
            <entry name="tcp-8443">
              <protocol>
                <tcp>
                  <port>8443</port>
                </tcp>
              </protocol>
              <description>Custom HTTPS alt port</description>
            </entry>
            <entry name="tcp-5432">
              <protocol>
                <tcp>
                  <port>5432</port>
                </tcp>
              </protocol>
              <description>PostgreSQL</description>
            </entry>
          </service>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-outbound-web">
                  <from>
                    <member>trust</member>
                  </from>
                  <to>
                    <member>untrust</member>
                  </to>
                  <source>
                    <member>internal-net</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                  </application>
                  <service>
                    <member>application-default</member>
                  </service>
                  <action>allow</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="allow-dns">
                  <from>
                    <member>trust</member>
                  </from>
                  <to>
                    <member>untrust</member>
                  </to>
                  <source>
                    <member>dns-server</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <application>
                    <member>dns</member>
                  </application>
                  <service>
                    <member>application-default</member>
                  </service>
                  <action>allow</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="allow-inbound-https">
                  <from>
                    <member>untrust</member>
                  </from>
                  <to>
                    <member>trust</member>
                  </to>
                  <source>
                    <member>any</member>
                  </source>
                  <destination>
                    <member>web-server-1</member>
                    <member>web-server-2</member>
                  </destination>
                  <application>
                    <member>ssl</member>
                  </application>
                  <service>
                    <member>application-default</member>
                  </service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="allow-inbound-alt-https">
                  <from>
                    <member>untrust</member>
                  </from>
                  <to>
                    <member>trust</member>
                  </to>
                  <source>
                    <member>any</member>
                  </source>
                  <destination>
                    <member>web-server-1</member>
                  </destination>
                  <application>
                    <member>any</member>
                  </application>
                  <service>
                    <member>tcp-8443</member>
                  </service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="allow-ssh-mgmt">
                  <from>
                    <member>trust</member>
                  </from>
                  <to>
                    <member>trust</member>
                  </to>
                  <source>
                    <member>internal-net</member>
                  </source>
                  <destination>
                    <member>web-server-1</member>
                    <member>web-server-2</member>
                    <member>db-server</member>
                  </destination>
                  <application>
                    <member>ssh</member>
                  </application>
                  <service>
                    <member>application-default</member>
                  </service>
                  <action>allow</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="deny-all">
                  <from>
                    <member>any</member>
                  </from>
                  <to>
                    <member>any</member>
                  </to>
                  <source>
                    <member>any</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <application>
                    <member>any</member>
                  </application>
                  <service>
                    <member>any</member>
                  </service>
                  <action>deny</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="outbound-nat">
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/2</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <from>
                    <member>trust</member>
                  </from>
                  <to>
                    <member>untrust</member>
                  </to>
                  <source>
                    <member>any</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`,
  },

  // =========================================================================
  // SAMPLE 2: Medium Branch Office
  // =========================================================================
  medium: {
    vendor: 'panos',
    label: 'Medium (12 rules)',
    description: 'Branch office: 3 zones (trust/untrust/dmz), address groups, service objects, 12 rules, 3 NAT',
    xml: `<?xml version="1.0"?>
<config version="10.2.0" urldb="paloaltonetworks">
  <devices>
    <entry name="branch-fw-01">
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust">
              <network>
                <layer3>
                  <member>ethernet1/1</member>
                </layer3>
              </network>
            </entry>
            <entry name="untrust">
              <network>
                <layer3>
                  <member>ethernet1/2</member>
                </layer3>
              </network>
            </entry>
            <entry name="dmz">
              <network>
                <layer3>
                  <member>ethernet1/3</member>
                </layer3>
              </network>
            </entry>
          </zone>
          <address>
            <entry name="app-server-1">
              <ip-netmask>172.16.10.10/32</ip-netmask>
            </entry>
            <entry name="app-server-2">
              <ip-netmask>172.16.10.11/32</ip-netmask>
            </entry>
            <entry name="mail-server">
              <ip-netmask>172.16.20.5/32</ip-netmask>
              <description>Exchange mail server</description>
            </entry>
            <entry name="proxy-server">
              <ip-netmask>172.16.20.10/32</ip-netmask>
            </entry>
            <entry name="dmz-web-1">
              <ip-netmask>192.168.100.10/32</ip-netmask>
              <description>Public web server in DMZ</description>
            </entry>
            <entry name="dmz-web-2">
              <ip-netmask>192.168.100.11/32</ip-netmask>
            </entry>
            <entry name="dmz-api">
              <ip-netmask>192.168.100.20/32</ip-netmask>
              <description>Public API gateway</description>
            </entry>
            <entry name="internal-subnet">
              <ip-netmask>172.16.0.0/16</ip-netmask>
            </entry>
            <entry name="dmz-subnet">
              <ip-netmask>192.168.100.0/24</ip-netmask>
            </entry>
            <entry name="partner-vpn-net">
              <ip-netmask>10.99.0.0/24</ip-netmask>
              <description>Partner VPN network range</description>
            </entry>
          </address>
          <address-group>
            <entry name="app-servers">
              <static>
                <member>app-server-1</member>
                <member>app-server-2</member>
              </static>
              <description>Application server cluster</description>
            </entry>
            <entry name="dmz-web-servers">
              <static>
                <member>dmz-web-1</member>
                <member>dmz-web-2</member>
              </static>
            </entry>
            <entry name="all-dmz-hosts">
              <static>
                <member>dmz-web-1</member>
                <member>dmz-web-2</member>
                <member>dmz-api</member>
              </static>
            </entry>
          </address-group>
          <service>
            <entry name="tcp-8080">
              <protocol>
                <tcp>
                  <port>8080</port>
                </tcp>
              </protocol>
              <description>HTTP alt port</description>
            </entry>
            <entry name="tcp-3000-3010">
              <protocol>
                <tcp>
                  <port>3000-3010</port>
                </tcp>
              </protocol>
              <description>Node.js app ports</description>
            </entry>
            <entry name="tcp-443-8443">
              <protocol>
                <tcp>
                  <port>443,8443</port>
                </tcp>
              </protocol>
              <description>HTTPS standard and alt</description>
            </entry>
            <entry name="udp-514">
              <protocol>
                <udp>
                  <port>514</port>
                </udp>
              </protocol>
              <description>Syslog</description>
            </entry>
          </service>
          <rulebase>
            <security>
              <rules>
                <entry name="trust-to-untrust-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>internal-subnet</member></source>
                  <destination><member>any</member></destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="trust-to-untrust-dns">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>dns</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="trust-to-dmz-app">
                  <from><member>trust</member></from>
                  <to><member>dmz</member></to>
                  <source><member>internal-subnet</member></source>
                  <destination><member>all-dmz-hosts</member></destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="dmz-to-trust-db">
                  <from><member>dmz</member></from>
                  <to><member>trust</member></to>
                  <source><member>dmz-api</member></source>
                  <destination><member>app-servers</member></destination>
                  <application><member>any</member></application>
                  <service><member>tcp-3000-3010</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="untrust-to-dmz-https">
                  <from><member>untrust</member></from>
                  <to><member>dmz</member></to>
                  <source><member>any</member></source>
                  <destination><member>dmz-web-servers</member></destination>
                  <application><member>ssl</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="untrust-to-dmz-api">
                  <from><member>untrust</member></from>
                  <to><member>dmz</member></to>
                  <source><member>any</member></source>
                  <destination><member>dmz-api</member></destination>
                  <application><member>ssl</member></application>
                  <service><member>tcp-443-8443</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="trust-to-trust-ssh">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>internal-subnet</member></source>
                  <destination><member>app-servers</member></destination>
                  <application><member>ssh</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <schedule>business-hours</schedule>
                </entry>
                <entry name="trust-to-untrust-mail">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>mail-server</member></source>
                  <destination><member>any</member></destination>
                  <application>
                    <member>smtp</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="untrust-to-trust-mail-inbound">
                  <from><member>untrust</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>mail-server</member></destination>
                  <application><member>smtp</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="trust-to-untrust-syslog">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>partner-vpn-net</member></destination>
                  <application><member>syslog</member></application>
                  <service><member>udp-514</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="dmz-to-untrust-updates">
                  <from><member>dmz</member></from>
                  <to><member>untrust</member></to>
                  <source><member>all-dmz-hosts</member></source>
                  <destination><member>any</member></destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <description>Allow DMZ servers to fetch OS updates</description>
                </entry>
                <entry name="deny-all">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>deny</action>
                  <log-end>yes</log-end>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="outbound-nat-trust">
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/2</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                </entry>
                <entry name="outbound-nat-dmz">
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/2</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <from><member>dmz</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                </entry>
                <entry name="inbound-nat-web">
                  <destination-translation>
                    <translated-address>192.168.100.10</translated-address>
                    <translated-port>443</translated-port>
                  </destination-translation>
                  <from><member>untrust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>dmz-web-1</member></destination>
                </entry>
              </rules>
            </nat>
          </rulebase>
          <schedule>
            <entry name="business-hours">
              <schedule-type>
                <recurring>
                  <weekly>
                    <monday>08:00-18:00</monday>
                    <tuesday>08:00-18:00</tuesday>
                    <wednesday>08:00-18:00</wednesday>
                    <thursday>08:00-18:00</thursday>
                    <friday>08:00-18:00</friday>
                  </weekly>
                </recurring>
              </schedule-type>
            </entry>
          </schedule>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`,
  },

  // =========================================================================
  // SAMPLE 3: Complex Enterprise
  // =========================================================================
  complex: {
    vendor: 'panos',
    label: 'Complex (19 rules)',
    description: 'Enterprise: 4 zones, custom apps, security profiles (UTM/IDP), EDL threat feeds (SecIntel), disabled rules, tags',
    xml: `<?xml version="1.0"?>
<config version="11.0.0" urldb="paloaltonetworks">
  <devices>
    <entry name="dc-fw-primary">
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust">
              <network><layer3><member>ethernet1/1</member></layer3></network>
            </entry>
            <entry name="untrust">
              <network><layer3><member>ethernet1/2</member></layer3></network>
            </entry>
            <entry name="dmz">
              <network><layer3><member>ethernet1/3</member></layer3></network>
            </entry>
            <entry name="mgmt">
              <network><layer3><member>ethernet1/4</member></layer3></network>
              <description>Management zone for network devices</description>
            </entry>
          </zone>
          <address>
            <entry name="dc-web-01"><ip-netmask>10.10.1.10/32</ip-netmask></entry>
            <entry name="dc-web-02"><ip-netmask>10.10.1.11/32</ip-netmask></entry>
            <entry name="dc-app-01"><ip-netmask>10.10.2.10/32</ip-netmask></entry>
            <entry name="dc-app-02"><ip-netmask>10.10.2.11/32</ip-netmask></entry>
            <entry name="dc-db-01"><ip-netmask>10.10.3.10/32</ip-netmask></entry>
            <entry name="dc-db-02"><ip-netmask>10.10.3.11/32</ip-netmask></entry>
            <entry name="jumpbox"><ip-netmask>10.10.99.5/32</ip-netmask><description>Bastion host</description></entry>
            <entry name="siem-server"><ip-netmask>10.10.99.10/32</ip-netmask></entry>
            <entry name="ntp-server"><ip-netmask>10.10.99.15/32</ip-netmask></entry>
            <entry name="internal-all"><ip-netmask>10.10.0.0/16</ip-netmask></entry>
            <entry name="dmz-net"><ip-netmask>192.168.200.0/24</ip-netmask></entry>
            <entry name="mgmt-net"><ip-netmask>10.10.99.0/24</ip-netmask></entry>
            <entry name="partner-net-a"><ip-netmask>10.200.1.0/24</ip-netmask><description>Partner A VPN</description></entry>
            <entry name="partner-net-b"><ip-netmask>10.200.2.0/24</ip-netmask><description>Partner B VPN</description></entry>
            <entry name="cdn-external"><fqdn>cdn.acmecorp.example.com</fqdn><description>CDN edge node</description></entry>
          </address>
          <address-group>
            <entry name="web-tier">
              <static>
                <member>dc-web-01</member>
                <member>dc-web-02</member>
              </static>
              <description>Web tier servers</description>
            </entry>
            <entry name="app-tier">
              <static>
                <member>dc-app-01</member>
                <member>dc-app-02</member>
              </static>
            </entry>
            <entry name="db-tier">
              <static>
                <member>dc-db-01</member>
                <member>dc-db-02</member>
              </static>
            </entry>
            <entry name="partner-networks">
              <static>
                <member>partner-net-a</member>
                <member>partner-net-b</member>
              </static>
            </entry>
          </address-group>
          <service>
            <entry name="tcp-8080"><protocol><tcp><port>8080</port></tcp></protocol></entry>
            <entry name="tcp-8443"><protocol><tcp><port>8443</port></tcp></protocol></entry>
            <entry name="tcp-3306"><protocol><tcp><port>3306</port></tcp></protocol><description>MySQL</description></entry>
            <entry name="tcp-5432"><protocol><tcp><port>5432</port></tcp></protocol><description>PostgreSQL</description></entry>
            <entry name="tcp-6379"><protocol><tcp><port>6379</port></tcp></protocol><description>Redis</description></entry>
            <entry name="tcp-9200"><protocol><tcp><port>9200</port></tcp></protocol><description>Elasticsearch</description></entry>
          </service>
          <application>
            <entry name="acme-internal-api">
              <description>ACME Corp internal REST API</description>
              <default>
                <port>
                  <member>tcp/8443</member>
                </port>
              </default>
            </entry>
            <entry name="acme-metrics">
              <description>ACME Corp metrics collection agent</description>
            </entry>
          </application>
          <external-list>
            <entry name="panw-bulletproof-ip-list">
              <type><predefined-ip><url>panw-bulletproof-ip-list</url></predefined-ip></type>
            </entry>
            <entry name="panw-highrisk-ip-list">
              <type><predefined-ip><url>panw-highrisk-ip-list</url></predefined-ip></type>
            </entry>
          </external-list>
          <rulebase>
            <security>
              <rules>
                <entry name="block-threat-feeds">
                  <from><member>untrust</member></from>
                  <to><member>trust</member><member>dmz</member></to>
                  <source><member>panw-bulletproof-ip-list</member><member>panw-highrisk-ip-list</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>deny</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <description>Block known malicious IPs from PAN-OS EDL feeds</description>
                </entry>
                <entry name="web-to-app-tier">
                  <from><member>dmz</member></from>
                  <to><member>trust</member></to>
                  <source><member>web-tier</member></source>
                  <destination><member>app-tier</member></destination>
                  <application><member>acme-internal-api</member></application>
                  <service><member>tcp-8443</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <tag><member>pci-scope</member><member>tier-link</member></tag>
                  <profile-setting>
                    <profiles>
                      <virus><member>default</member></virus>
                      <spyware><member>strict</member></spyware>
                      <vulnerability><member>strict</member></vulnerability>
                      <url-filtering><member>corporate-url-filter</member></url-filtering>
                      <file-blocking><member>strict file blocking</member></file-blocking>
                      <wildfire-analysis><member>default</member></wildfire-analysis>
                    </profiles>
                  </profile-setting>
                </entry>
                <entry name="app-to-db-mysql">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>app-tier</member></source>
                  <destination><member>dc-db-01</member></destination>
                  <application><member>any</member></application>
                  <service><member>tcp-3306</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <tag><member>pci-scope</member></tag>
                </entry>
                <entry name="app-to-db-postgres">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>app-tier</member></source>
                  <destination><member>dc-db-02</member></destination>
                  <application><member>any</member></application>
                  <service><member>tcp-5432</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <tag><member>pci-scope</member></tag>
                </entry>
                <entry name="app-to-redis">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>app-tier</member></source>
                  <destination><member>app-tier</member></destination>
                  <application><member>any</member></application>
                  <service><member>tcp-6379</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="inbound-web-https">
                  <from><member>untrust</member></from>
                  <to><member>dmz</member></to>
                  <source><member>any</member></source>
                  <destination><member>web-tier</member></destination>
                  <application><member>ssl</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <profile-setting>
                    <profiles>
                      <virus><member>default</member></virus>
                      <spyware><member>strict</member></spyware>
                      <vulnerability><member>strict</member></vulnerability>
                    </profiles>
                  </profile-setting>
                </entry>
                <entry name="inbound-web-http-redirect">
                  <from><member>untrust</member></from>
                  <to><member>dmz</member></to>
                  <source><member>any</member></source>
                  <destination><member>web-tier</member></destination>
                  <application><member>web-browsing</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <description>Allow HTTP for redirect to HTTPS</description>
                </entry>
                <entry name="mgmt-ssh-all">
                  <from><member>mgmt</member></from>
                  <to><member>trust</member><member>dmz</member></to>
                  <source><member>jumpbox</member></source>
                  <destination><member>any</member></destination>
                  <application><member>ssh</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="mgmt-to-siem">
                  <from><member>trust</member><member>dmz</member><member>mgmt</member></from>
                  <to><member>mgmt</member></to>
                  <source><member>any</member></source>
                  <destination><member>siem-server</member></destination>
                  <application><member>syslog</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="all-to-ntp">
                  <from><member>trust</member><member>dmz</member><member>mgmt</member></from>
                  <to><member>mgmt</member></to>
                  <source><member>any</member></source>
                  <destination><member>ntp-server</member></destination>
                  <application><member>ntp</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="trust-to-dns">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>internal-all</member></source>
                  <destination><member>any</member></destination>
                  <application><member>dns</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="outbound-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>internal-all</member></source>
                  <destination><member>any</member></destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="partner-a-access">
                  <from><member>untrust</member></from>
                  <to><member>trust</member></to>
                  <source><member>partner-net-a</member></source>
                  <destination><member>app-tier</member></destination>
                  <application><member>acme-internal-api</member></application>
                  <service><member>tcp-8443</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <description>Partner A API integration</description>
                </entry>
                <entry name="partner-b-access">
                  <from><member>untrust</member></from>
                  <to><member>trust</member></to>
                  <source><member>partner-net-b</member></source>
                  <destination><member>app-tier</member></destination>
                  <application><member>acme-internal-api</member></application>
                  <service><member>tcp-8443</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <description>Partner B API integration</description>
                </entry>
                <entry name="elasticsearch-access">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>app-tier</member></source>
                  <destination><member>siem-server</member></destination>
                  <application><member>any</member></application>
                  <service><member>tcp-9200</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="dmz-outbound-updates">
                  <from><member>dmz</member></from>
                  <to><member>untrust</member></to>
                  <source><member>dmz-net</member></source>
                  <destination><member>any</member></destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <description>DMZ OS/package updates</description>
                </entry>
                <entry name="deprecated-ftp-rule">
                  <from><member>trust</member></from>
                  <to><member>dmz</member></to>
                  <source><member>internal-all</member></source>
                  <destination><member>dmz-net</member></destination>
                  <application><member>ftp</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <disabled>yes</disabled>
                  <log-end>yes</log-end>
                  <description>DEPRECATED - migrated to SFTP</description>
                </entry>
                <entry name="old-test-rule">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                  <disabled>yes</disabled>
                  <log-end>yes</log-end>
                  <description>DISABLED - was used for testing</description>
                </entry>
                <entry name="deny-all">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>deny</action>
                  <log-end>yes</log-end>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="outbound-snat">
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/2</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                </entry>
                <entry name="dmz-outbound-snat">
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/2</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <from><member>dmz</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                </entry>
                <entry name="inbound-dnat-web">
                  <destination-translation>
                    <translated-address>10.10.1.10</translated-address>
                    <translated-port>443</translated-port>
                  </destination-translation>
                  <from><member>untrust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>dc-web-01</member></destination>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`,
  },

  // =========================================================================
  // SAMPLE 4: Edge Cases
  // =========================================================================
  edgeCases: {
    vendor: 'panos',
    label: 'Edge Cases (8 rules)',
    description: 'Tricky constructs: FQDN objects, any/any, tags, dynamic groups, drop actions, IP ranges',
    xml: `<?xml version="1.0"?>
<config version="10.1.0" urldb="paloaltonetworks">
  <devices>
    <entry name="edge-test-fw">
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="inside">
              <network><layer3><member>ethernet1/1</member></layer3></network>
            </entry>
            <entry name="outside">
              <network><layer3><member>ethernet1/2</member></layer3></network>
            </entry>
          </zone>
          <address>
            <entry name="cloud-api">
              <fqdn>api.cloudservice.example.com</fqdn>
              <description>External cloud API endpoint</description>
            </entry>
            <entry name="cdn-edge">
              <fqdn>edge.cdn.example.com</fqdn>
            </entry>
            <entry name="scanner-range">
              <ip-range>10.50.0.1-10.50.0.254</ip-range>
              <description>Vulnerability scanner pool</description>
            </entry>
            <entry name="legacy-server">
              <ip-netmask>10.1.100.5/32</ip-netmask>
              <description>Legacy server - decomm scheduled</description>
            </entry>
            <entry name="user-vlan">
              <ip-netmask>10.1.0.0/22</ip-netmask>
            </entry>
            <entry name="server-vlan">
              <ip-netmask>10.1.100.0/24</ip-netmask>
            </entry>
          </address>
          <address-group>
            <entry name="dynamic-cloud-hosts">
              <dynamic>
                <filter>'cloud-tagged'</filter>
              </dynamic>
              <description>Dynamic group based on cloud tags</description>
            </entry>
            <entry name="all-servers">
              <static>
                <member>legacy-server</member>
                <member>server-vlan</member>
              </static>
            </entry>
          </address-group>
          <service>
            <entry name="tcp-9090">
              <protocol><tcp><port>9090</port></tcp></protocol>
              <description>Prometheus metrics</description>
            </entry>
          </service>
          <rulebase>
            <security>
              <rules>
                <entry name="any-any-permit-test">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                  <disabled>yes</disabled>
                  <log-end>yes</log-end>
                  <description>DISABLED test rule - do not enable</description>
                  <tag><member>test</member><member>do-not-delete</member></tag>
                </entry>
                <entry name="cloud-api-access">
                  <from><member>inside</member></from>
                  <to><member>outside</member></to>
                  <source><member>server-vlan</member></source>
                  <destination><member>cloud-api</member></destination>
                  <application><member>ssl</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <description>Servers to cloud API over HTTPS</description>
                </entry>
                <entry name="cdn-access">
                  <from><member>inside</member></from>
                  <to><member>outside</member></to>
                  <source><member>user-vlan</member></source>
                  <destination><member>cdn-edge</member></destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="scanner-to-servers">
                  <from><member>inside</member></from>
                  <to><member>inside</member></to>
                  <source><member>scanner-range</member></source>
                  <destination><member>all-servers</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <description>Vulnerability scanning access</description>
                  <tag><member>security-scanning</member></tag>
                </entry>
                <entry name="drop-inbound-scanners">
                  <from><member>outside</member></from>
                  <to><member>inside</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>tcp-9090</member></service>
                  <action>drop</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <description>Drop external attempts to reach metrics</description>
                </entry>
                <entry name="reset-bad-actors">
                  <from><member>outside</member></from>
                  <to><member>inside</member></to>
                  <source><member>any</member></source>
                  <destination><member>legacy-server</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>reset-both</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                  <description>RST connection attempts to decommissioned server</description>
                </entry>
                <entry name="outbound-general">
                  <from><member>inside</member></from>
                  <to><member>outside</member></to>
                  <source><member>user-vlan</member></source>
                  <destination><member>any</member></destination>
                  <application>
                    <member>web-browsing</member>
                    <member>ssl</member>
                    <member>dns</member>
                  </application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="deny-all">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>deny</action>
                  <log-end>yes</log-end>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="outbound-snat">
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/2</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <from><member>inside</member></from>
                  <to><member>outside</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`,
  },

  // =========================================================================
  // SAMPLE 5: Real-World Production (sanitized)
  // =========================================================================
  realworld: {
    vendor: 'panos',
    label: 'Real-World (23 rules)',
    description: 'Production PA-440: 5 zones, EDL threat feeds, geo-negate blocking, 3 security profile groups, VPN tunnel zone, application groups, 23 security rules, 3 NAT rules',
    xml: `<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <application-group>
            <entry name="MGT-Applications">
              <members>
                <member>icmp</member>
                <member>ssh</member>
                <member>ssl</member>
                <member>web-browsing</member>
                <member>ping</member>
              </members>
            </entry>
            <entry name="AC-Internet-Applications">
              <members>
                <member>adobe-cloud</member>
                <member>apple-push-notifications</member>
                <member>boxnet</member>
                <member>dns</member>
                <member>dns-over-https</member>
                <member>dropbox</member>
                <member>facebook</member>
                <member>gmail</member>
                <member>google-base</member>
                <member>google-play</member>
                <member>icloud</member>
                <member>lastpass</member>
                <member>ldap</member>
                <member>linkedin</member>
                <member>ms-office365</member>
                <member>ms-onedrive</member>
                <member>ms-teams</member>
                <member>ms-update</member>
                <member>ntp</member>
                <member>ocsp</member>
                <member>outlook-web-online</member>
                <member>ping</member>
                <member>quic</member>
                <member>sharepoint-online</member>
                <member>spotify</member>
                <member>ssl</member>
                <member>stun</member>
                <member>web-browsing</member>
                <member>windows-azure</member>
                <member>zoom</member>
              </members>
            </entry>
            <entry name="PaloAlto-Applications">
              <members>
                <member>dns</member>
                <member>google-base</member>
                <member>ntp</member>
                <member>ocsp</member>
                <member>paloalto-device-telemetry</member>
                <member>paloalto-dns-security</member>
                <member>paloalto-shared-services</member>
                <member>paloalto-updates</member>
                <member>paloalto-wildfire-cloud</member>
                <member>pan-db-cloud</member>
                <member>panorama</member>
                <member>ssl</member>
                <member>web-browsing</member>
              </members>
            </entry>
          </application-group>
          <zone>
            <entry name="Internet-Side">
              <network>
                <layer3>
                  <member>ethernet1/1</member>
                </layer3>
              </network>
            </entry>
            <entry name="Default-LAN-Side">
              <network>
                <layer3>
                  <member>ethernet1/2</member>
                  <member>tunnel.1</member>
                </layer3>
              </network>
            </entry>
            <entry name="MGT-Net">
              <network>
                <layer3>
                  <member>ethernet1/8</member>
                </layer3>
              </network>
            </entry>
            <entry name="DMZ">
              <network>
                <layer3>
                  <member>ethernet1/7</member>
                </layer3>
              </network>
            </entry>
            <entry name="Server-Network">
              <network>
                <layer3>
                  <member>ethernet1/3</member>
                </layer3>
              </network>
            </entry>
          </zone>
          <service>
            <entry name="Panorama-SSL-3978">
              <protocol><tcp><port>443,3978</port><override><no/></override></tcp></protocol>
            </entry>
            <entry name="DirectoryLDAP">
              <protocol><tcp><port>636</port><override><no/></override></tcp></protocol>
            </entry>
            <entry name="BackupCloud-Endpoint-Mgr">
              <protocol><tcp><port>9079</port><override><no/></override></tcp></protocol>
              <description>Backup Endpoint Manager</description>
            </entry>
            <entry name="BackupCloud-Server">
              <protocol><tcp><port>9082</port><override><no/></override></tcp></protocol>
              <description>Backup Cloud Server</description>
            </entry>
            <entry name="BackupCloud-DRAL">
              <protocol><tcp><port>9083</port><override><no/></override></tcp></protocol>
              <description>Backup Disaster Recovery Access Layer</description>
            </entry>
            <entry name="BackupCloud-Manager">
              <protocol><tcp><port>9090</port><override><no/></override></tcp></protocol>
              <description>Backup Manager</description>
            </entry>
            <entry name="NAS-Web-Admin-5000">
              <protocol><tcp><port>5000</port><override><no/></override></tcp></protocol>
              <description>NAS Server Web Admin</description>
            </entry>
            <entry name="ssl4318">
              <protocol><tcp><port>4318</port><override><no/></override></tcp></protocol>
            </entry>
            <entry name="rdp-3389">
              <protocol><tcp><port>3389</port><override><no/></override></tcp></protocol>
            </entry>
            <entry name="gpu-cluster-8443">
              <protocol><tcp><port>8443</port><override><no/></override></tcp></protocol>
            </entry>
          </service>
          <service-group>
            <entry name="BackupCloud-D2C-Services">
              <members>
                <member>BackupCloud-Manager</member>
                <member>BackupCloud-Server</member>
                <member>BackupCloud-DRAL</member>
                <member>BackupCloud-Endpoint-Mgr</member>
                <member>service-http</member>
                <member>service-https</member>
              </members>
            </entry>
            <entry name="AC-Services-Internal-NAS">
              <members>
                <member>NAS-Web-Admin-5000</member>
              </members>
            </entry>
          </service-group>
          <rulebase>
            <security>
              <rules>
                <entry name="DROP Inbound Bulletproof High Risk">
                  <to><member>any</member></to>
                  <from><member>any</member></from>
                  <source>
                    <member>panw-bulletproof-ip-list</member>
                    <member>panw-highrisk-ip-list</member>
                    <member>panw-known-ip-list</member>
                    <member>panw-torexit-ip-list</member>
                  </source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>drop</action>
                </entry>
                <entry name="DROP Inbound Countries - Negate">
                  <to><member>any</member></to>
                  <from><member>any</member></from>
                  <source>
                    <member>10.0.0.0-10.255.255.255</member>
                    <member>172.16.0.0-172.31.255.255</member>
                    <member>192.168.0.0-192.168.255.255</member>
                    <member>AU</member>
                    <member>MY</member>
                    <member>US</member>
                  </source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>drop</action>
                  <negate-source>yes</negate-source>
                  <description>Drop ALL inbound countries except listed here including US and private ranges. Addresses are negated from Any.</description>
                </entry>
                <entry name="DROP Outbound Bulletproof High Risk">
                  <to><member>any</member></to>
                  <from><member>any</member></from>
                  <source><member>any</member></source>
                  <destination>
                    <member>panw-bulletproof-ip-list</member>
                    <member>panw-highrisk-ip-list</member>
                    <member>panw-known-ip-list</member>
                    <member>panw-torexit-ip-list</member>
                  </destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>drop</action>
                </entry>
                <entry name="DROP Outbound Countries - Negate">
                  <to><member>any</member></to>
                  <from><member>any</member></from>
                  <source><member>any</member></source>
                  <destination>
                    <member>10.0.0.0-10.255.255.255</member>
                    <member>172.16.0.0-172.31.255.255</member>
                    <member>192.168.0.0-192.168.255.255</member>
                    <member>AU</member>
                    <member>CA</member>
                    <member>DE</member>
                    <member>EU</member>
                    <member>GB</member>
                    <member>JP</member>
                    <member>US</member>
                  </destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>drop</action>
                  <negate-destination>yes</negate-destination>
                  <disabled>no</disabled>
                </entry>
                <entry name="ALLOW PaloAlto-Applications">
                  <from><member>MGT-Net</member></from>
                  <to><member>Internet-Side</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>PaloAlto-Applications</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
                <entry name="ALLOW PaloAlto-Panorama-SSL">
                  <from><member>MGT-Net</member></from>
                  <to><member>Internet-Side</member></to>
                  <source><member>any</member></source>
                  <destination><member>Cloud-Panorama</member></destination>
                  <service><member>application-default</member></service>
                  <application>
                    <member>panorama</member>
                    <member>ssl</member>
                  </application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                  <log-start>no</log-start>
                </entry>
                <entry name="ALLOW PaloAlto-Panorama-SSL-TEMP-OPEN">
                  <from><member>MGT-Net</member></from>
                  <to><member>Internet-Side</member></to>
                  <source><member>any</member></source>
                  <destination><member>Cloud-Panorama</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <log-start>no</log-start>
                </entry>
                <entry name="ALLOW Server-Directory">
                  <from><member>Server-Network</member></from>
                  <to><member>Internet-Side</member></to>
                  <source><member>Server-Gamma</member></source>
                  <destination>
                    <member>ldap-mfa.idp.example.com</member>
                    <member>ldap.idp.example.com</member>
                  </destination>
                  <service><member>DirectoryLDAP</member></service>
                  <application>
                    <member>ldap</member>
                    <member>ssl</member>
                  </application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
                <entry name="ALLOW FW-Directory">
                  <from><member>MGT-Net</member></from>
                  <to><member>Internet-Side</member></to>
                  <source><member>any</member></source>
                  <destination>
                    <member>ldap-mfa.idp.example.com</member>
                    <member>ldap.idp.example.com</member>
                  </destination>
                  <service><member>DirectoryLDAP</member></service>
                  <application>
                    <member>ldap</member>
                    <member>ssl</member>
                  </application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
                <entry name="ALLOW MGT from Local LAN">
                  <from><member>Default-LAN-Side</member></from>
                  <to><member>MGT-Net</member></to>
                  <source><member>AC-Network</member></source>
                  <destination><member>MGT-Network</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>MGT-Applications</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
                <entry name="ALLOW AC Server Internet Apps">
                  <from><member>Server-Network</member></from>
                  <to><member>Internet-Side</member></to>
                  <source><member>AC-Servers</member></source>
                  <destination><member>any</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>ssl</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>NAS-Cloud-Domains</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                  <disabled>no</disabled>
                </entry>
                <entry name="ALLOW AC Internet Applications">
                  <from><member>Default-LAN-Side</member></from>
                  <to><member>Internet-Side</member></to>
                  <source><member>AC-Network</member></source>
                  <destination><member>any</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>AC-Internet-Applications</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
                <entry name="ALLOW AC Internal Apps NAS">
                  <from><member>Default-LAN-Side</member></from>
                  <to><member>Server-Network</member></to>
                  <source><member>AC-Network</member></source>
                  <destination><member>Server-Gamma</member></destination>
                  <service><member>AC-Services-Internal-NAS</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                  <source-hip><member>any</member></source-hip>
                  <disabled>no</disabled>
                </entry>
                <entry name="ALLOW AC Internal SMB">
                  <from>
                    <member>Default-LAN-Side</member>
                    <member>Server-Network</member>
                  </from>
                  <to>
                    <member>Default-LAN-Side</member>
                    <member>Server-Network</member>
                  </to>
                  <source>
                    <member>AC-Network</member>
                    <member>AC-Server-Network</member>
                  </source>
                  <destination>
                    <member>AC-Server-Network</member>
                    <member>AC-Servers</member>
                  </destination>
                  <service><member>any</member></service>
                  <application>
                    <member>4shared</member>
                    <member>ms-ds-smb-base</member>
                    <member>ms-ds-smbv2</member>
                    <member>ms-ds-smbv3</member>
                    <member>netbios-dg</member>
                    <member>netbios-ns</member>
                    <member>netbios-ss</member>
                    <member>print-over-ms-smb</member>
                    <member>ssl</member>
                    <member>web-browsing</member>
                  </application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <destination-hip><member>any</member></destination-hip>
                  <source-hip><member>any</member></source-hip>
                  <option>
                    <disable-server-response-inspection>yes</disable-server-response-inspection>
                  </option>
                </entry>
                <entry name="ALLOW AC Internal Applications">
                  <from><member>Default-LAN-Side</member></from>
                  <to><member>Server-Network</member></to>
                  <source><member>AC-Network</member></source>
                  <destination><member>AC-Servers</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Internal</member></group>
                  </profile-setting>
                  <source-hip><member>any</member></source-hip>
                </entry>
                <entry name="ALLOW BackupCloud D2C">
                  <from>
                    <member>Default-LAN-Side</member>
                    <member>Server-Network</member>
                  </from>
                  <to><member>Internet-Side</member></to>
                  <source><member>any</member></source>
                  <destination><member>BackupCloud IP Addresses</member></destination>
                  <service><member>BackupCloud-D2C-Services</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
                <entry name="ALLOW Outbound All">
                  <from>
                    <member>Default-LAN-Side</member>
                    <member>MGT-Net</member>
                    <member>Server-Network</member>
                  </from>
                  <to><member>Internet-Side</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
                <entry name="ALLOW from LAN to Server SSH">
                  <to><member>Server-Network</member></to>
                  <from><member>Default-LAN-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>ssh</member></application>
                  <service><member>any</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>allow</action>
                </entry>
                <entry name="ALLOW from LAN cotp">
                  <to><member>Server-Network</member></to>
                  <from><member>Default-LAN-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>cotp</member></application>
                  <service><member>application-default</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>allow</action>
                </entry>
                <entry name="ALLOW from LAN ssl on 4318">
                  <to><member>Server-Network</member></to>
                  <from><member>Default-LAN-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>ssl</member></application>
                  <service><member>ssl4318</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>allow</action>
                </entry>
                <entry name="ALLOW from LAN t120 and rdp on 3389">
                  <to><member>Server-Network</member></to>
                  <from><member>Default-LAN-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application>
                    <member>ms-rdp</member>
                    <member>t.120</member>
                  </application>
                  <service><member>rdp-3389</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>allow</action>
                </entry>
                <entry name="Allow inbound for Web App">
                  <to><member>Server-Network</member></to>
                  <from><member>Internet-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>Web-App-Public-Host</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>any</member></application>
                  <service><member>application-default</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>allow</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="Allow from user to server">
                  <to><member>Server-Network</member></to>
                  <from><member>Default-LAN-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                  <action>allow</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="Internet Outgoing NAT Policy">
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/1</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <to><member>Internet-Side</member></to>
                  <from>
                    <member>Default-LAN-Side</member>
                    <member>MGT-Net</member>
                    <member>Server-Network</member>
                  </from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service>any</service>
                  <description>Internet Outgoing NAT Policy</description>
                  <to-interface>any</to-interface>
                </entry>
                <entry name="NAT-WebApp-Inbound">
                  <to><member>Internet-Side</member></to>
                  <from><member>Internet-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>Web-App-Public-Host</member></destination>
                  <service>any</service>
                  <description>NAT rule for inbound web application traffic.</description>
                  <to-interface>any</to-interface>
                  <destination-translation>
                    <translated-address>Server-Delta</translated-address>
                  </destination-translation>
                </entry>
                <entry name="NAT-WebApp-HTTP">
                  <to><member>Internet-Side</member></to>
                  <from><member>Internet-Side</member></from>
                  <source><member>any</member></source>
                  <destination><member>Web-App-Public-Host</member></destination>
                  <service>service-http</service>
                  <description>NAT rule for HTTP web application with port translation.</description>
                  <to-interface>any</to-interface>
                  <destination-translation>
                    <translated-port>80</translated-port>
                    <translated-address>Server-Delta</translated-address>
                  </destination-translation>
                  <disabled>yes</disabled>
                </entry>
              </rules>
            </nat>
            <default-security-rules>
              <rules>
                <entry name="interzone-default">
                  <action>deny</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="intrazone-default">
                  <action>allow</action>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                  <profile-setting>
                    <group><member>Acme-Security-Profile</member></group>
                  </profile-setting>
                </entry>
              </rules>
            </default-security-rules>
          </rulebase>
          <address>
            <entry name="ISP-WAN-Link">
              <ip-netmask>198.51.100.9/27</ip-netmask>
              <description>Acme Corp WAN Connection</description>
            </entry>
            <entry name="AC-GW">
              <ip-netmask>10.10.10.1/24</ip-netmask>
            </entry>
            <entry name="MGT-GW">
              <ip-netmask>172.31.255.1/25</ip-netmask>
              <description>Management Network</description>
            </entry>
            <entry name="ISP-Gateway">
              <ip-netmask>198.51.100.1</ip-netmask>
              <description>Default Route</description>
            </entry>
            <entry name="AC-Network">
              <ip-netmask>10.10.10.0/24</ip-netmask>
            </entry>
            <entry name="MGT-Network">
              <ip-netmask>172.31.255.0/25</ip-netmask>
            </entry>
            <entry name="Cloud-Panorama">
              <fqdn>panorama.mgmt.example.com</fqdn>
            </entry>
            <entry name="ldap.idp.example.com">
              <fqdn>ldap.idp.example.com</fqdn>
            </entry>
            <entry name="ldap-mfa.idp.example.com">
              <fqdn>ldap-mfa.idp.example.com</fqdn>
            </entry>
            <entry name="Server-Alpha">
              <ip-netmask>192.168.0.4/32</ip-netmask>
            </entry>
            <entry name="Server-Beta">
              <ip-netmask>192.168.0.5/32</ip-netmask>
            </entry>
            <entry name="Server-Gamma">
              <ip-netmask>192.168.0.7/32</ip-netmask>
            </entry>
            <entry name="Server-Delta">
              <ip-netmask>192.168.0.8/32</ip-netmask>
            </entry>
            <entry name="Server-Epsilon">
              <ip-netmask>192.168.0.9/32</ip-netmask>
            </entry>
            <entry name="Server-Zeta">
              <ip-netmask>192.168.0.13/32</ip-netmask>
            </entry>
            <entry name="Server-Eta">
              <ip-netmask>192.168.0.14/32</ip-netmask>
            </entry>
            <entry name="Server-Theta">
              <ip-netmask>192.168.0.15/32</ip-netmask>
            </entry>
            <entry name="Server-Iota">
              <ip-netmask>192.168.0.17/32</ip-netmask>
            </entry>
            <entry name="Server-Kappa">
              <ip-netmask>192.168.0.141/32</ip-netmask>
            </entry>
            <entry name="AC-Server-GW">
              <ip-netmask>192.168.0.1/24</ip-netmask>
            </entry>
            <entry name="AC-Server-Network">
              <ip-netmask>192.168.0.0/24</ip-netmask>
            </entry>
            <entry name="BackupCloud-IP-203.0.113.0">
              <ip-netmask>203.0.113.0/26</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="BackupCloud-IP-203.0.113.64">
              <ip-netmask>203.0.113.64/26</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="BackupCloud-IP-203.0.113.128">
              <ip-netmask>203.0.113.128/26</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="BackupCloud-IP-203.0.113.192">
              <ip-netmask>203.0.113.192/26</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="BackupCloud-IP-192.0.2.0">
              <ip-netmask>192.0.2.0/26</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="BackupCloud-IP-192.0.2.64">
              <ip-netmask>192.0.2.64/26</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="BackupCloud-IP-192.0.2.128">
              <ip-netmask>192.0.2.128/25</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="BackupCloud-IP-192.0.2.192">
              <ip-netmask>192.0.2.192/26</ip-netmask>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="NAS-Cloud-AWS">
              <ip-netmask>203.0.113.10/32</ip-netmask>
            </entry>
            <entry name="NAS-Cloud-EU">
              <ip-netmask>203.0.113.11/32</ip-netmask>
            </entry>
            <entry name="Web-App-Public">
              <ip-netmask>198.51.100.10/27</ip-netmask>
            </entry>
            <entry name="Web-App-Public-Host">
              <ip-netmask>198.51.100.10/32</ip-netmask>
            </entry>
          </address>
          <profile-group>
            <entry name="Internet">
              <virus><member>default</member></virus>
              <spyware><member>default</member></spyware>
              <vulnerability><member>default</member></vulnerability>
              <url-filtering><member>default</member></url-filtering>
              <file-blocking><member>basic file blocking</member></file-blocking>
              <wildfire-analysis><member>default</member></wildfire-analysis>
            </entry>
            <entry name="Acme-Security-Profile">
              <virus><member>default</member></virus>
              <spyware><member>strict-1</member></spyware>
              <vulnerability><member>strict</member></vulnerability>
              <url-filtering><member>default-1</member></url-filtering>
              <file-blocking><member>basic file blocking</member></file-blocking>
              <wildfire-analysis><member>default</member></wildfire-analysis>
            </entry>
            <entry name="Acme-Security-Internal">
              <virus><member>default</member></virus>
              <spyware><member>strict</member></spyware>
              <vulnerability><member>strict</member></vulnerability>
              <url-filtering><member>default</member></url-filtering>
              <file-blocking><member>AC-basic file blocking</member></file-blocking>
              <wildfire-analysis><member>default</member></wildfire-analysis>
            </entry>
          </profile-group>
          <address-group>
            <entry name="AC-Servers">
              <static>
                <member>Server-Iota</member>
                <member>Server-Gamma</member>
                <member>Server-Epsilon</member>
                <member>Server-Zeta</member>
                <member>Server-Kappa</member>
                <member>Server-Alpha</member>
                <member>Server-Eta</member>
                <member>Server-Beta</member>
                <member>Server-Theta</member>
                <member>Server-Delta</member>
              </static>
            </entry>
            <entry name="BackupCloud IP Addresses">
              <static>
                <member>BackupCloud-IP-203.0.113.0</member>
                <member>BackupCloud-IP-203.0.113.64</member>
                <member>BackupCloud-IP-203.0.113.128</member>
                <member>BackupCloud-IP-203.0.113.192</member>
                <member>BackupCloud-IP-192.0.2.0</member>
                <member>BackupCloud-IP-192.0.2.64</member>
                <member>BackupCloud-IP-192.0.2.128</member>
                <member>BackupCloud-IP-192.0.2.192</member>
              </static>
              <description>Backup Cloud IP addresses</description>
            </entry>
            <entry name="NAS-Cloud-Servers">
              <static>
                <member>NAS-Cloud-AWS</member>
                <member>NAS-Cloud-EU</member>
              </static>
            </entry>
          </address-group>
          <profiles>
            <custom-url-category>
              <entry name="NAS-Cloud-Domains">
                <list>
                  <member>*.box.com/</member>
                  <member>*.app.box.com/</member>
                  <member>*.ent.box.com/</member>
                  <member>*.box.net/</member>
                  <member>*.boxcdn.net/</member>
                  <member>*.boxcloud.com/</member>
                </list>
                <type>URL List</type>
                <description>NAS Cloud Domains used for Cloud Services</description>
              </entry>
              <entry name="CloudStorage">
                <list>
                  <member>*.cloudstorage.example.com/</member>
                </list>
                <type>URL List</type>
              </entry>
            </custom-url-category>
            <file-blocking>
              <entry name="AC-basic file blocking">
                <rules>
                  <entry name="Block high risk file types">
                    <application><member>any</member></application>
                    <file-type>
                      <member>bat</member>
                      <member>chm</member>
                      <member>class</member>
                      <member>cpl</member>
                      <member>hlp</member>
                      <member>hta</member>
                      <member>ocx</member>
                      <member>PE</member>
                      <member>pif</member>
                      <member>rar</member>
                      <member>scr</member>
                      <member>torrent</member>
                      <member>vbe</member>
                      <member>wsf</member>
                    </file-type>
                    <direction>both</direction>
                    <action>block</action>
                  </entry>
                  <entry name="Continue prompt encrypted files">
                    <application><member>any</member></application>
                    <file-type>
                      <member>7z</member>
                      <member>dll</member>
                      <member>encrypted-7z</member>
                      <member>encrypted-rar</member>
                      <member>encrypted-zip</member>
                      <member>exe</member>
                      <member>jar</member>
                    </file-type>
                    <direction>both</direction>
                    <action>continue</action>
                  </entry>
                  <entry name="Log all other file types">
                    <application><member>any</member></application>
                    <file-type><member>any</member></file-type>
                    <direction>both</direction>
                    <action>alert</action>
                  </entry>
                </rules>
              </entry>
            </file-blocking>
            <url-filtering>
              <entry name="default-1">
                <credential-enforcement>
                  <mode><disabled/></mode>
                  <log-severity>medium</log-severity>
                </credential-enforcement>
                <alert>
                  <member>artificial-intelligence</member>
                  <member>cryptocurrency</member>
                  <member>high-risk</member>
                  <member>medium-risk</member>
                  <member>newly-registered-domain</member>
                  <member>real-time-detection</member>
                </alert>
                <block>
                  <member>abused-drugs</member>
                  <member>adult</member>
                  <member>command-and-control</member>
                  <member>gambling</member>
                  <member>hacking</member>
                  <member>malware</member>
                  <member>phishing</member>
                  <member>ransomware</member>
                  <member>weapons</member>
                </block>
              </entry>
            </url-filtering>
            <spyware>
              <entry name="strict-1">
                <rules>
                  <entry name="simple-critical">
                    <action><reset-both/></action>
                    <severity><member>critical</member></severity>
                    <threat-name>any</threat-name>
                    <category>any</category>
                    <packet-capture>disable</packet-capture>
                  </entry>
                  <entry name="simple-high">
                    <action><reset-both/></action>
                    <severity><member>high</member></severity>
                    <threat-name>any</threat-name>
                    <category>any</category>
                    <packet-capture>disable</packet-capture>
                  </entry>
                  <entry name="simple-medium">
                    <action><reset-both/></action>
                    <severity><member>medium</member></severity>
                    <threat-name>any</threat-name>
                    <category>any</category>
                    <packet-capture>disable</packet-capture>
                  </entry>
                  <entry name="simple-informational">
                    <action><default/></action>
                    <severity><member>informational</member></severity>
                    <threat-name>any</threat-name>
                    <category>any</category>
                    <packet-capture>disable</packet-capture>
                  </entry>
                  <entry name="simple-low">
                    <action><alert/></action>
                    <severity><member>low</member></severity>
                    <threat-name>any</threat-name>
                    <category>any</category>
                    <packet-capture>disable</packet-capture>
                  </entry>
                </rules>
                <botnet-domains>
                  <lists>
                    <entry name="default-paloalto-dns">
                      <action><sinkhole/></action>
                      <packet-capture>disable</packet-capture>
                    </entry>
                  </lists>
                  <sinkhole>
                    <ipv4-address>pan-sinkhole-default-ip</ipv4-address>
                    <ipv6-address>::1</ipv6-address>
                  </sinkhole>
                </botnet-domains>
              </entry>
            </spyware>
          </profiles>
          <external-list>
            <entry name="panw-bulletproof-ip-list">
              <type><predefined-ip><url>panw-bulletproof-ip-list</url></predefined-ip></type>
            </entry>
            <entry name="panw-highrisk-ip-list">
              <type><predefined-ip><url>panw-highrisk-ip-list</url></predefined-ip></type>
            </entry>
            <entry name="panw-known-ip-list">
              <type><predefined-ip><url>panw-known-ip-list</url></predefined-ip></type>
            </entry>
            <entry name="panw-torexit-ip-list">
              <type><predefined-ip><url>panw-torexit-ip-list</url></predefined-ip></type>
            </entry>
          </external-list>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`,
  },

  // =========================================================================
  // SAMPLE 6: SRX Set Commands (Junos)
  // =========================================================================
  srx_basic: {
    vendor: 'srx',
    label: 'SRX Basic (6 rules)',
    description: 'SRX set commands: 3 zones, address objects, 6 security policies, source NAT',
    xml: `set version 21.4R3-S5.4
set system host-name srx550-branch01

set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone trust interfaces ge-0/0/1.0
set security zones security-zone untrust interfaces ge-0/0/2.0
set security zones security-zone dmz interfaces ge-0/0/3.0

set security address-book global address web-server-1 10.10.10.10/32
set security address-book global address web-server-2 10.10.10.11/32
set security address-book global address app-server-1 10.20.20.10/32
set security address-book global address db-server-1 10.30.30.10/32
set security address-book global address dns-server 10.1.1.53/32
set security address-book global address internal-net 192.168.0.0/16
set security address-book global address dmz-net 10.10.10.0/24
set security address-book global address-set web-servers address web-server-1
set security address-book global address-set web-servers address web-server-2
set security address-book global address-set all-servers address web-server-1
set security address-book global address-set all-servers address web-server-2
set security address-book global address-set all-servers address app-server-1
set security address-book global address-set all-servers address db-server-1

set security policies from-zone trust to-zone untrust policy allow-internet match source-address any
set security policies from-zone trust to-zone untrust policy allow-internet match destination-address any
set security policies from-zone trust to-zone untrust policy allow-internet match application junos-http
set security policies from-zone trust to-zone untrust policy allow-internet match application junos-https
set security policies from-zone trust to-zone untrust policy allow-internet match application junos-dns-udp
set security policies from-zone trust to-zone untrust policy allow-internet then permit
set security policies from-zone trust to-zone untrust policy allow-internet then log session-close

set security policies from-zone untrust to-zone dmz policy allow-web match source-address any
set security policies from-zone untrust to-zone dmz policy allow-web match destination-address web-servers
set security policies from-zone untrust to-zone dmz policy allow-web match application junos-http
set security policies from-zone untrust to-zone dmz policy allow-web match application junos-https
set security policies from-zone untrust to-zone dmz policy allow-web then permit
set security policies from-zone untrust to-zone dmz policy allow-web then log session-init
set security policies from-zone untrust to-zone dmz policy allow-web then log session-close

set security policies from-zone trust to-zone dmz policy trust-to-dmz match source-address internal-net
set security policies from-zone trust to-zone dmz policy trust-to-dmz match destination-address dmz-net
set security policies from-zone trust to-zone dmz policy trust-to-dmz match application any
set security policies from-zone trust to-zone dmz policy trust-to-dmz then permit
set security policies from-zone trust to-zone dmz policy trust-to-dmz then log session-close
set security policies from-zone trust to-zone dmz policy trust-to-dmz scheduler-name weekday-business

set security policies from-zone dmz to-zone trust policy dmz-to-db match source-address app-server-1
set security policies from-zone dmz to-zone trust policy dmz-to-db match destination-address db-server-1
set security policies from-zone dmz to-zone trust policy dmz-to-db match application junos-mysql
set security policies from-zone dmz to-zone trust policy dmz-to-db then permit
set security policies from-zone dmz to-zone trust policy dmz-to-db then log session-close

set security policies from-zone trust to-zone untrust policy allow-dns match source-address any
set security policies from-zone trust to-zone untrust policy allow-dns match destination-address any
set security policies from-zone trust to-zone untrust policy allow-dns match application junos-dns-udp
set security policies from-zone trust to-zone untrust policy allow-dns then permit

set security policies from-zone untrust to-zone trust policy deny-all match source-address any
set security policies from-zone untrust to-zone trust policy deny-all match destination-address any
set security policies from-zone untrust to-zone trust policy deny-all match application any
set security policies from-zone untrust to-zone trust policy deny-all then deny
set security policies from-zone untrust to-zone trust policy deny-all then log session-close

set security nat source rule-set trust-to-untrust from zone trust
set security nat source rule-set trust-to-untrust to zone untrust
set security nat source rule-set trust-to-untrust rule source-nat-rule match source-address 0.0.0.0/0
set security nat source rule-set trust-to-untrust rule source-nat-rule then source-nat interface

set applications application custom-app-8080 protocol tcp
set applications application custom-app-8080 destination-port 8080

set schedulers scheduler weekday-business monday start-time 08:00:00 stop-time 18:00:00
set schedulers scheduler weekday-business tuesday start-time 08:00:00 stop-time 18:00:00
set schedulers scheduler weekday-business wednesday start-time 08:00:00 stop-time 18:00:00
set schedulers scheduler weekday-business thursday start-time 08:00:00 stop-time 18:00:00
set schedulers scheduler weekday-business friday start-time 08:00:00 stop-time 18:00:00`,
  },

  // =========================================================================
  // SAMPLE 7: FortiGate / FortiOS Configuration
  // =========================================================================
  fortigate_basic: {
    vendor: 'fortigate',
    label: 'FortiGate Basic (8 rules)',
    description: 'FortiGate config: 3 zones, address objects, 8 firewall policies, VIP, security profiles',
    xml: `config system global
    set hostname "FG-60F-Branch01"
    set timezone "US/Pacific"
end

config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.1 255.255.255.0
        set type physical
        set alias "WAN-Primary"
    next
    edit "wan2"
        set vdom "root"
        set ip 198.51.100.1 255.255.255.0
        set type physical
        set alias "WAN-Secondary"
    next
    edit "dmz"
        set vdom "root"
        set ip 172.16.10.1 255.255.255.0
        set type physical
        set alias "DMZ-Servers"
    next
    edit "internal1"
        set vdom "root"
        set ip 10.1.1.1 255.255.255.0
        set type physical
        set alias "LAN-Users"
    next
    edit "internal2"
        set vdom "root"
        set ip 10.1.2.1 255.255.255.0
        set type physical
        set alias "LAN-Servers"
    next
end

config system zone
    edit "LAN"
        set interface "internal1" "internal2"
    next
    edit "WAN"
        set interface "wan1" "wan2"
    next
    edit "DMZ"
        set interface "dmz"
    next
end

config firewall address
    edit "WebServer1"
        set type ipmask
        set subnet 172.16.10.10 255.255.255.255
        set comment "Primary web server"
    next
    edit "WebServer2"
        set type ipmask
        set subnet 172.16.10.11 255.255.255.255
        set comment "Secondary web server"
    next
    edit "DBServer"
        set type ipmask
        set subnet 10.1.2.50 255.255.255.255
        set comment "PostgreSQL database"
    next
    edit "LAN-Subnet"
        set type ipmask
        set subnet 10.1.0.0 255.255.0.0
        set comment "All LAN networks"
    next
    edit "MailServer"
        set type ipmask
        set subnet 172.16.10.20 255.255.255.255
        set comment "Exchange mail server"
    next
    edit "DNS-Servers"
        set type ipmask
        set subnet 10.1.2.53 255.255.255.255
        set comment "Internal DNS"
    next
    edit "Guest-WiFi"
        set type ipmask
        set subnet 10.1.100.0 255.255.255.0
        set comment "Guest wireless network"
    next
    edit "VPN-Pool"
        set type iprange
        set start-ip 10.10.10.1
        set end-ip 10.10.10.254
        set comment "SSL VPN address pool"
    next
end

config firewall addrgrp
    edit "DMZ-Servers"
        set member "WebServer1" "WebServer2" "MailServer"
        set comment "All DMZ servers"
    next
    edit "Internal-Servers"
        set member "DBServer" "DNS-Servers"
        set comment "Internal server group"
    next
end

config firewall service custom
    edit "Web-Services"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 80 443 8080 8443
        set comment "HTTP and HTTPS variants"
    next
    edit "DB-Access"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 5432 3306
        set comment "PostgreSQL and MySQL"
    next
end

config firewall service group
    edit "Internet-Services"
        set member "HTTP" "HTTPS" "DNS"
    next
end

config firewall vip
    edit "WebServer1-VIP"
        set type static-nat
        set extip 203.0.113.10
        set mappedip "172.16.10.10"
        set extintf "wan1"
        set portforward enable
        set extport 443
        set mappedport 443
        set comment "HTTPS to WebServer1"
    next
    edit "MailServer-VIP"
        set type static-nat
        set extip 203.0.113.20
        set mappedip "172.16.10.20"
        set extintf "wan1"
        set portforward enable
        set extport 25
        set mappedport 25
        set comment "SMTP to mail server"
    next
end

config firewall schedule recurring
    edit "office-hours"
        set day monday tuesday wednesday thursday friday
        set start 08:00
        set end 18:00
    next
end

config firewall policy
    edit 1
        set name "LAN-to-Internet"
        set uuid 11111111-1111-1111-1111-111111111111
        set srcintf "LAN"
        set dstintf "WAN"
        set action accept
        set srcaddr "LAN-Subnet"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set av-profile "default"
        set webfilter-profile "default"
        set ips-sensor "default"
        set application-list "default"
        set ssl-ssh-profile "certificate-inspection"
        set logtraffic all
        set nat enable
        set comments "Allow LAN users to internet with full UTM"
    next
    edit 2
        set name "DMZ-to-Internet"
        set uuid 22222222-2222-2222-2222-222222222222
        set srcintf "DMZ"
        set dstintf "WAN"
        set action accept
        set srcaddr "DMZ-Servers"
        set dstaddr "all"
        set schedule "always"
        set service "Internet-Services"
        set utm-status enable
        set av-profile "default"
        set ips-sensor "default"
        set logtraffic all
        set nat enable
        set comments "DMZ servers to internet for updates"
    next
    edit 3
        set name "Inbound-HTTPS"
        set uuid 33333333-3333-3333-3333-333333333333
        set srcintf "WAN"
        set dstintf "DMZ"
        set action accept
        set srcaddr "all"
        set dstaddr "WebServer1-VIP"
        set schedule "always"
        set service "HTTPS"
        set utm-status enable
        set av-profile "default"
        set ips-sensor "default"
        set ssl-ssh-profile "deep-inspection"
        set logtraffic all
        set comments "Inbound HTTPS to web server via VIP"
    next
    edit 4
        set name "Inbound-SMTP"
        set uuid 44444444-4444-4444-4444-444444444444
        set srcintf "WAN"
        set dstintf "DMZ"
        set action accept
        set srcaddr "all"
        set dstaddr "MailServer-VIP"
        set schedule "always"
        set service "SMTP"
        set utm-status enable
        set av-profile "default"
        set ips-sensor "default"
        set logtraffic all
        set comments "Inbound SMTP to mail server"
    next
    edit 5
        set name "LAN-to-DMZ"
        set uuid 55555555-5555-5555-5555-555555555555
        set srcintf "LAN"
        set dstintf "DMZ"
        set action accept
        set srcaddr "LAN-Subnet"
        set dstaddr "DMZ-Servers"
        set schedule "office-hours"
        set service "Web-Services"
        set logtraffic all
        set comments "LAN access to DMZ servers"
    next
    edit 6
        set name "DMZ-to-DB"
        set uuid 66666666-6666-6666-6666-666666666666
        set srcintf "DMZ"
        set dstintf "LAN"
        set action accept
        set srcaddr "WebServer1" "WebServer2"
        set dstaddr "DBServer"
        set schedule "always"
        set service "DB-Access"
        set utm-status enable
        set ips-sensor "default"
        set logtraffic all
        set comments "Web servers to database"
    next
    edit 7
        set name "Guest-Internet-Only"
        set uuid 77777777-7777-7777-7777-777777777777
        set srcintf "LAN"
        set dstintf "WAN"
        set action accept
        set srcaddr "Guest-WiFi"
        set dstaddr "all"
        set schedule "always"
        set service "Internet-Services"
        set utm-status enable
        set webfilter-profile "default"
        set logtraffic all
        set nat enable
        set comments "Guest WiFi internet only — no internal access"
    next
    edit 8
        set name "Deny-All"
        set uuid 88888888-8888-8888-8888-888888888888
        set srcintf "any"
        set dstintf "any"
        set action deny
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set comments "Implicit deny-all cleanup rule"
    next
end`,
  },

  // =========================================================================
  // SAMPLE: Cisco ASA Basic
  // =========================================================================
  cisco_basic: {
    vendor: 'cisco_asa',
    label: 'Basic (8 rules)',
    description: 'Cisco ASA: 3 zones, object networks, object-groups, 8 ACL rules, NAT',
    xml: `ASA Version 9.16
!
hostname FW-EDGE-01
!
interface GigabitEthernet1/1
 nameif inside
 security-level 100
 ip address 10.1.1.1 255.255.255.0
!
interface GigabitEthernet1/2
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.252
!
interface GigabitEthernet1/3
 nameif dmz
 security-level 50
 ip address 172.16.1.1 255.255.255.0
!
object network web-server
 host 172.16.1.10
 description Primary web server in DMZ
object network mail-server
 host 172.16.1.20
 description Exchange mail server
object network internal-net
 subnet 10.1.0.0 255.255.0.0
 description Internal corporate network
object network db-server
 host 10.1.2.50
 description PostgreSQL database server
object network dns-server
 host 10.1.1.53
 description Internal DNS resolver
object network guest-net
 subnet 10.99.0.0 255.255.255.0
 description Guest WiFi network
!
object-group network DMZ-SERVERS
 network-object object web-server
 network-object object mail-server
object-group network INTERNAL-ALL
 network-object object internal-net
 network-object object guest-net
!
object-group service WEB-SERVICES tcp
 port-object eq www
 port-object eq https
object-group service MAIL-SERVICES tcp
 port-object eq smtp
 port-object eq 993
 port-object eq 587
object-group service MGMT-SERVICES tcp
 port-object eq ssh
 port-object eq 3389
!
time-range BUSINESS-HOURS
 periodic weekdays 08:00 to 18:00
!
access-list outside_access_in extended remark Allow inbound web traffic to DMZ
access-list outside_access_in extended permit tcp any object web-server object-group WEB-SERVICES log
access-list outside_access_in extended remark Allow inbound mail
access-list outside_access_in extended permit tcp any object mail-server object-group MAIL-SERVICES log
access-list outside_access_in extended remark Deny all other inbound
access-list outside_access_in extended deny ip any any log
!
access-list inside_access_in extended remark Allow internal to internet
access-list inside_access_in extended permit tcp object internal-net any object-group WEB-SERVICES
access-list inside_access_in extended remark Allow DNS
access-list inside_access_in extended permit udp object internal-net any eq domain
access-list inside_access_in extended remark Allow internal to DMZ servers
access-list inside_access_in extended permit tcp object internal-net object-group DMZ-SERVERS object-group WEB-SERVICES
access-list inside_access_in extended remark Allow MGMT to servers (business hours only)
access-list inside_access_in extended permit tcp 10.1.1.0 255.255.255.0 object-group DMZ-SERVERS object-group MGMT-SERVICES time-range BUSINESS-HOURS
access-list inside_access_in extended remark Deny all other internal
access-list inside_access_in extended deny ip any any log
!
access-group outside_access_in in interface outside
access-group inside_access_in in interface inside
!
object network internal-net
 nat (inside,outside) dynamic interface
object network web-server
 nat (dmz,outside) static 203.0.113.10
object network mail-server
 nat (dmz,outside) static 203.0.113.20
`,
  },
};
