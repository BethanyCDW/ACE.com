#! /bin/bash
sudo su
yum update -y
yum install httpd -y
systemctl start httpd
systemctl enable httpd
echo "Hello from App Server 2" > /var/www/html/index.html