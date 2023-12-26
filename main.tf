terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}


################################################################################
# Virtual Private Clouds
################################################################################
module "vpc1" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "network-vpc1"
  cidr = "10.10.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.10.1.0/24", "10.10.2.0/24"]
  public_subnets  = ["10.10.3.0/24", "10.10.4.0/24"]

 
  enable_nat_gateway = true
  enable_vpn_gateway = true
  one_nat_gateway_per_az = true
  single_nat_gateway = false
 

  tags = {
    name = "Network VPC"
  }
}
module "vpc2" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "application-vpc2"
  cidr = "10.20.0.0/16"

  azs             = ["us-east-1a", "us-east-1b",]
  private_subnets = ["10.20.1.0/24", "10.20.2.0/24"]
  public_subnets = ["10.20.3.0/24", "10.20.4.0/24"]
  enable_ipv6 = false

  enable_nat_gateway = true
  enable_vpn_gateway = true
  one_nat_gateway_per_az = true
  single_nat_gateway = false
  enable_dns_support = true
  enable_dns_hostnames = true
  private_subnet_enable_resource_name_dns_a_record_on_launch = true
  tags = {
    name = "Application VPC"
  }
}

################################################################################
# Four EC2 Instances
################################################################################
module "ec2_instance1" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = "application-webserver1"

  instance_type          = "t2.large"
  monitoring             = true
  subnet_id = module.vpc2.private_subnets[0]
  
  availability_zone = "us-east-1a"
  user_data = file("script-app1.sh")
  key_name = "example-key"
  vpc_security_group_ids = [aws_security_group.allow-all-app.id]
  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
module "ec2_instance2" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = "app-server-jump1"

  instance_type          = "t2.large"
  monitoring             = true
  subnet_id = module.vpc2.public_subnets[0]
  associate_public_ip_address = true
  availability_zone = "us-east-1a"
  key_name = "example-key"
  vpc_security_group_ids = [aws_security_group.allow-all-vpc1.id]
  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
module "ec2_instance3" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = "application-webserver2"

  instance_type          = "t2.large"
  monitoring             = true
  subnet_id = module.vpc2.private_subnets[1]
  
  availability_zone = "us-east-1b"
  key_name = "example-key"
  user_data = file("script-app2.sh")
  vpc_security_group_ids = [aws_security_group.allow-all-app.id]
  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
module "ec2_instance4" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = "app-server-jump2"

  instance_type          = "t2.large"
  monitoring             = true
  subnet_id = module.vpc2.public_subnets[1]
  associate_public_ip_address = true
  availability_zone = "us-east-1b"
  key_name = "example-key"
  vpc_security_group_ids = [aws_security_group.allow-all-vpc1.id]
  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
################################################################################
# RDS Database 
################################################################################
module "db" {
  source = "terraform-aws-modules/rds/aws"

  identifier = "appdb"

  engine            = "mysql"
  engine_version    = "5.7"
  instance_class    = "db.m5.xlarge"
  allocated_storage = 5

  db_name  = "Application_DB"
  username = "user"
  port     = "3306"

  iam_database_authentication_enabled = true

  maintenance_window = "Mon:00:00-Mon:03:00"
  backup_window      = "03:00-06:00"
  multi_az = true
  backup_retention_period = "35"
  

  monitoring_interval    = "30"
  monitoring_role_name   = "MyRDSMonitoringRole"
  create_monitoring_role = true

  tags = {
    Owner       = "user"
    Environment = "prod"
  }

  # DB subnet group
  create_db_subnet_group = true
  subnet_ids             = module.vpc2.private_subnets
  

  # DB parameter group
  family = "mysql5.7"

  # DB option group
  major_engine_version = "5.7"

  # Database Deletion Protection
  deletion_protection = false

  parameters = [
    {
      name  = "character_set_client"
      value = "utf8mb4"
    },
    {
      name  = "character_set_server"
      value = "utf8mb4"
    }
    
  ]

}
################################################################################
# Transit Gateway
################################################################################
module "tgw" {
  source  = "terraform-aws-modules/transit-gateway/aws"
  name            = "tgw"
  description     = "My TGW shared with VPCs"

  transit_gateway_cidr_blocks = ["10.99.0.0/24"]

  
  enable_auto_accept_shared_attachments = true

  
  enable_multicast_support = false

  vpc_attachments = {
    vpc1 = {
      vpc_id       = module.vpc1.vpc_id
      subnet_ids   = module.vpc1.private_subnets
      dns_support  = true
      ipv6_support = false

      transit_gateway_default_route_table_association = true
      transit_gateway_default_route_table_propagation = true

      tgw_routes = [
        {
          destination_cidr_block = "30.0.0.0/16"
        },
        {
          blackhole              = true
          destination_cidr_block = "0.0.0.0/0"
        }
      ]
      tags = {
        Name = "network-vpc1-attachment"
      }
    },
    vpc2 = {
      vpc_id     = module.vpc2.vpc_id
      subnet_ids = module.vpc2.private_subnets
      dns_support  = true
      ipv6_support = false

      transit_gateway_default_route_table_association = true
      transit_gateway_default_route_table_propagation = true

      tgw_routes = [
        {
          destination_cidr_block = "50.0.0.0/16"
        },
        {
          blackhole              = true
          destination_cidr_block = "10.10.10.10/32"
        }
      ]
      tags = {
        Name = "application-vpc2-attachment"
      }
    },
  }

  ram_allow_external_principals = true
  ram_principals                = [307990089504]

}
################################################################################
# Security Groups
################################################################################
resource "aws_security_group" "allow-all-vpc1" {
  name        = "jumphost-sg"
  description = "Allow all inbound traffic"
  vpc_id      = module.vpc2.vpc_id


  ingress {
    description      = "all from VPC"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = null
  }

    egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "jumphost-sg"
  }
}

resource "aws_security_group" "allow-all-app" {
  provider    = aws
  vpc_id      = module.vpc2.vpc_id
  name        = "app-sg"
  description = "Allow all inbound traffic"


  ingress {
    description      = "all from VPC"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = null
  }
    ingress {
    description      = "web servers"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["10.20.0.0/16"]
    ipv6_cidr_blocks = null
  }

    egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "app-sg"
  }
}
resource "aws_security_group" "alb-sg" {
  name        = "alb-sg"
  description = "Security group for the alb"
  vpc_id      = module.vpc2.vpc_id

  ingress {
    cidr_blocks = [
      "0.0.0.0/0",
    ]
    from_port = 443
    protocol  = "tcp"
    to_port   = 445
  }
  ingress {
    cidr_blocks = [
      "0.0.0.0/0",
    ]
    from_port = 80
    protocol  = "tcp"
  
    to_port   = 82
  }
    egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}


################################################################################
# Network Firewall 
################################################################################

module "network_firewall" {
  source = "terraform-aws-modules/network-firewall/aws//modules/firewall"


  # Firewall
  name        = "example"
  description = "Example network firewall"

  vpc_id = module.vpc1.vpc_id
  subnet_mapping = {
    subnet1 = {
      subnet_id       = module.vpc1.private_subnets[0]
      ip_address_type = "IPV4"
    }
    subnet2 = {
      subnet_id       = module.vpc1.private_subnets[1]
      ip_address_type = "IPV4"
    }
  
  }

firewall_policy_arn = aws_networkfirewall_firewall_policy.example.arn

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }

}


##########Pol
resource "aws_networkfirewall_firewall_policy" "example" {
    name         = "pol"

    firewall_policy {
        stateful_default_actions           = [
            "aws:drop_established",
        ]
        stateless_default_actions          = [
            "aws:forward_to_sfe",
        ]
        stateless_fragment_default_actions = [
            "aws:forward_to_sfe",
        ]

        policy_variables {
        }

        stateful_engine_options {
            rule_order              = "STRICT_ORDER"
            stream_exception_policy = "DROP"
        }

        stateful_rule_group_reference {
            priority     = 1
            resource_arn = aws_networkfirewall_rule_group.example.arn
        }
    }
}


#RG
resource "aws_networkfirewall_rule_group" "example" {
    capacity     = 100
    name         = "rg1"
    type         = "STATEFUL"
    
    rule_group {
        rules_source {
            stateful_rule {
                action = "PASS"

                header {
                    destination      = "ANY"
                    destination_port = "ANY"
                    direction        = "ANY"
                    protocol         = "IP"
                    source           = "ANY"
                    source_port      = "ANY"
                }

                rule_option {
                    keyword  = "sid"
                    settings = [
                        "1",
                    ]
                }
            }
        }
        stateful_rule_options {
            rule_order = "STRICT_ORDER"
        }
    }
}

################################################################################
# App Load Balancer
################################################################################
resource "aws_lb" "ace-app_load_balancer" {
  name               = "ace-app-load-balancer"
  internal           = false
  security_groups    = [aws_security_group.alb-sg.id]
  subnets = module.vpc2.public_subnets
  idle_timeout       = 30
  enable_deletion_protection = false
}

resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.ace-app_load_balancer.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.web.arn
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
      message_body = "OK"
    }
  }
}


resource "aws_lb_target_group" "web" {
  name     = "web-target-group"
  port     = 80
  target_type = "instance"
  protocol = "HTTP"
  vpc_id   = module.vpc2.vpc_id

  health_check {
    enabled             = true
    interval            = 30
    matcher             = "200-399"
    path                = "/index.html"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 3
    unhealthy_threshold = 2
    healthy_threshold   = 2
  }
  
}

resource "aws_lb_target_group_attachment" "attachment" {

  target_group_arn = aws_lb_target_group.web.arn
  target_id        = module.ec2_instance1.id
  port             = 80
}
resource "aws_lb_target_group_attachment" "attachment2" {

  target_group_arn = aws_lb_target_group.web.arn
  target_id        = module.ec2_instance3.id
  port             = 80
}


resource "aws_route_table" "app_public_route_table" {
  vpc_id = module.vpc2.vpc_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = module.vpc2.igw_id
  }

  tags = {
    Name = "AppPublicRouteTable"
  }
}
resource "aws_acm_certificate" "ace_domain" {
  domain_name       = "ace.com"
  validation_method = "DNS"


  lifecycle {
    create_before_destroy = true
  }
}