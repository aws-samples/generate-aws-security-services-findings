sudo yum update -y
sudo yum install docker -y
sudo yum install jq -y
sudo systemctl enable docker.service
sudo systemctl start docker.service

cat <<'EOF' >> /home/ec2-user/docker-vulnhub-image-list.txt
vulhub/wordpress:4.6
vulhub/tomcat:9.0.30
vulhub/weblogic:12.2.1.3-2018
vulhub/fastjson:1.2.24
vulhub/struts2:2.5.25
vulhub/thinkphp:5.0.20
vulhub/php:8.1-backdoor
vulhub/activemq:5.11.1-with-cron
vulhub/jboss:as-4.0.5
vulhub/nginx:heartbleed
vulhub/phpmyadmin:4.8.1
vulhub/hadoop:2.8.1
vulhub/solr:8.8.1
vulhub/elasticsearch:5.6.16
vulhub/python:2.7.7
vulhub/zabbix:3.0.3-web
vulhub/drupal:7.31
vulhub/redis:4.0.14
vulhub/couchdb:2.1.0
vulhub/flask:1.1.1
vulhub/shiro:1.5.1
vulhub/imagemagick:6.9.2-10-php
vulhub/jenkins:2.46.1
vulhub/spring-data-commons:2.0.5
vulhub/spring-data-commons:2.0.5
vulhub/ecshop:2.7.3
vulhub/java:15-jdk
vulhub/coldfusion:8.0.1
vulhub/discuz:7.2
vulhub/glassfish:4.1
vulhub/mysql:5.6.5
vulhub/cron:latest
vulhub/bind:latest
vulhub/libssh:0.8.1
vulhub/nexus:3.21.1
vulhub/webmin:1.910
vulhub/baselinux:centos-6
vulhub/samba:4.6.3
vulhub/confluence:7.4.10
vulhub/django:3.2.4
vulhub/bash:4.3.0-with-httpd
vulhub/goahead:3.6.4
vulhub/httpd:2.4-with-ssi
vulhub/spring-security-oauth2:2.0.8
vulhub/joomla:3.7.0
vulhub/spring-rest-data:2.6.6
vulhub/appweb:7.0.1
vulhub/ghostscript:9.53.3
vulhub/ffmpeg:2.8.4-with-php
vulhub/docker:18.03.0
vulhub/jupyter-notebook:5.2.2
vulhub/rsync:3.1.2
vulhub/ffmpeg:2.8.4-with-php
vulhub/postgres:10.7
vulhub/gogs:0.11.66
vulhub/spring-messaging:5.0.4
vulhub/flink:1.11.2
vulhub/node:8.5.0
vulhub/spring-with-jackson:2.8.8
vulhub/saltstack:2019.2.3
vulhub/spring-webflow:2.4.4
vulhub/oracle:12c-ee
vulhub/jmeter:3.3
vulhub/gitlab:8.13.1
vulhub/uwsgi-php:2.0.16
vulhub/spark:2.3.1
vulhub/log4j:2.8.1
vulhub/apereo-cas:4.1.5
vulhub/mini_httpd:1.29
vulhub/openssh:7.7
vulhub/electron:wine
vulhub/openjdk:oracle-jdk-6
vulhub/gitea:1.4.0
vulhub/spring-with-h2database:1.4.200

EOF

cat <<'EOF' >> /home/ec2-user/pull-upload-vulnhub-container-images.sh
# script to pull down vulnerable docker images from the
# vulnerables repository on docker hub and then store them
# in ECR to use for inspector scanning.
# This script works on a list of images from the vulhub repository.
# This is using a list of images because they are not using the latest tag
# So thhere is a need to reference specific images.


#first get the ECR creds
sudo chmod 666 /var/run/docker.sock

account=`curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .accountId`
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $account.dkr.ecr.us-east-1.amazonaws.com

for i in `cat /home/ec2-user/docker-vulnhub-image-list.txt`
do
        echo '***********'
        echo 'pulling image: ' $i
        docker pull $i

        image_base_name=`echo $i|awk -F ":" '{print $1}'`

        # Create a repository in ECR where the downloaded image will be stored

    echo 'Creating repository: vuln-images/'$image_base_name
        aws ecr create-repository --repository-name vuln-images/$image_base_name --region us-east-1 --tags Key=inspector-demo,Value=true

        # now upload the image to ECR

    echo 'Tagging image'
        docker tag $i $account.dkr.ecr.us-east-1.amazonaws.com/vuln-images/$image_base_name:latest

        echo 'Pushing image to ECR'
        docker push $account.dkr.ecr.us-east-1.amazonaws.com/vuln-images/$image_base_name:latest

done

EOF

sudo chmod +x /home/ec2-user/pull-upload-vulnhub-container-images.sh
sudo chmod 744 /home/ec2-user/pull-upload-vulnhub-container-images.sh
sudo chown ec2-user /home/ec2-user/pull-upload-vulnhub-container-images.sh
sudo echo "0 8 2 * * /home/ec2-user/pull-upload-vulnhub-container-images.sh" >> cron
sudo crontab -u ec2-user cron
sudo /home/ec2-user/pull-upload-vulnhub-container-images.sh