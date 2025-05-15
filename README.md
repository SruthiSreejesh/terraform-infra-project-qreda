# AWS Infrastructure Deployment with Terraform

###### This repository contains Terraform configurations to provision a scalable and secure AWS infrastructure. The setup includes VPCs, subnets, internet and NAT gateways, security groups, EC2 instances, load balancers, auto-scaling groups, and Route 53 DNS records.

## Overview

This Terraform project provisions a scalable and secure AWS infrastructure tailored for the **Qreda** application. The infrastructure includes the following key components:

1. **Virtual Private Cloud (VPC)**  
   A dedicated VPC to isolate the environment and manage networking resources securely.

2. **Subnets**  
   - Three **Public Subnets** across multiple Availability Zones to host resources accessible from the internet (e.g., Bastion Host, Load Balancer).  
   - Three **Private Subnets** distributed across the same Availability Zones to host backend resources without direct internet exposure (e.g., Application Servers).

   
     To ensure high availability and fault tolerance, the infrastructure spans three Availability Zones. This redundancy helps maintain service continuity in case of an AZ failure.

3. **Route Tables, Internet Gateway, and NAT Gateway**  
   - Public subnets are routed to the Internet Gateway allowing inbound and outbound internet traffic.  
   - Private subnets use a NAT Gateway deployed in one of the public subnets to enable outbound internet access for updates and patches while preventing inbound internet traffic for security.

4. **Security Groups**  
   Custom security groups restrict inbound and outbound traffic to EC2 instances, ensuring only authorized communication is allowed.

5. **Bastion Host**  
   A Bastion Host deployed in a public subnet provides secure SSH access to instances in private subnets without exposing them directly to the internet.

6. **Application Load Balancer (ALB)**  
   The ALB distributes incoming application traffic across multiple EC2 instances to achieve high availability and load balancing.

7. **Auto Scaling Group (ASG)**  
   The ASG dynamically adjusts the number of EC2 instances based on traffic and load, ensuring scalability and optimal resource utilization.

8. **IAM Role for Terraform Execution**  
   Terraform is executed from an EC2 instance with an attached IAM Role, enhancing security by avoiding the use of hardcoded AWS credentials (access keys and secrets).

This architecture ensures a secure, resilient, and highly available environment capable of supporting production workloads with fault tolerance and scalability.

---

## Architecture-diagram
```hcl

+--------------------------------------------------------------+
|                             VPC                              |
|                      CIDR: var.cidr_block                     |
|                                                              |
|  +------------------+            +---------------------+    |
|  |   Internet       |            |   Elastic IP (EIP)  |    |
|  |                  |            |     (For NAT GW)    |    |
|  +--------+---------+            +----------+----------+    |
|           |                                 |               |
|   +-------v-----------------+   +-----------v------------+  |
|   |   Internet Gateway (IGW) |  |   NAT Gateway          |  |
|   +------------+-------------+  +-----------+------------+  |
|                |                           |               |
|   +------------v-------------+             |               |
|   |     Public Route Table    |             |               |
|   +------------+-------------+             |               |
|                |                           |               |
|  +-------------+--------------+   +--------v---------+     |
|  |                            |   | Private Route    |     |
|  |       Public Subnets        |   | Table with NAT   |     |
|  |     (3 Subnets in 3 AZs)   |   +--------+--------+     |
|  |                            |            |              |
|  | +---------+ +---------+ +---------+    |              |
|  | | Pub Sub | | Pub Sub | | Pub Sub |    |              |
|  | | 1 (AZ1) | | 2 (AZ2) | | 3 (AZ3) |    |              |
|  | +----+----+ +----+----+ +----+----+    |              |
|  |      |          |          |           |              |
|  |  +---v---+  +---v---+  +---v---+       |              |
|  |  | Bastion|  |  ALB  |  |  ALB  |       |              |
|  |  | Host   |  | (AZ2) |  | (AZ3) |       |              |
|  |  +-------+  +-------+  +-------+       |              |
|  |      |          |          |           |              |
|  |      |      +---v---+      |           |              |
|  |      |      |  ALB  |      |           |              |
|  |      |      | (AZ1) |      |           |              |
|  |      |      +-------+      |           |              |
|  +------+----------+----------+-----------+--------------+
|                                                              |
|  +--------------------------+                                |
|  |       Private Subnets     |                                |
|  |      (3 Subnets in 3 AZs) |                               |
|  |                          |                                |
|  | +---------+ +---------+ +---------+                      |
|  | | Priv Sub| | Priv Sub| | Priv Sub|                      |
|  | | 1 (AZ1) | | 2 (AZ2) | | 3 (AZ3) |                      |
|  | +----+----+ +----+----+ +----+----+                      |
|  |      |          |          |                               |
|  |  +---v----------v----------v---+                           |
|  |  |      Auto Scaling Group     |                           |
|  |  |  launching EC2 instances    |                           |
|  |  +-----------------------------+                           |
|  +------------------------------------------------------------+
+--------------------------------------------------------------+
```

## Prerequisites

1. **AWS Account**  
   You need an active AWS account to create and manage AWS resources.

2. **Terraform Installed**  
   Install Terraform (version 1.0 or higher recommended) on your local machine or the server where you will run the infrastructure code.  
   [Terraform Installation Guide](https://learn.hashicorp.com/tutorials/terraform/install-cli)

3. **IAM Role Attached to Instance**  
   - Terraform should be executed on an AWS EC2 instance with an **IAM Role** attached that has sufficient permissions to create and manage the specified AWS resources.  
   - This avoids the need to use AWS access keys or secrets directly, enhancing security by leveraging **Instance Profile-based authentication**.

4. **Basic AWS Knowledge**  
   Familiarity with AWS VPCs, Subnets, Route Tables, Security Groups, EC2 instances, Load Balancers, and Auto Scaling concepts.

5. **Terraform Configuration Files**  
   Download or clone the repository containing the Terraform configuration files before running the Terraform commands.

6. **Networking Setup**  
   Ensure no overlapping IP ranges with existing VPCs in your AWS account to prevent conflicts.

7. **SSH Key Pair**  
   Create or have access to an AWS EC2 Key Pair to connect to EC2 instances such as the Bastion Host after deployment.

## Project Structure
```
├── provider.tf
├── variables.tf
├── production.tfvars
├── datasource.tf
├── main.tf
├── instances.tf
├── bastion.tf
├── launchtemplate.tf
├── lb.tf
├── autoscaling.tf
├── route53.tf
└── output.tf
```


## Terraform Configuration Files

#### 📄 provider.tf
```hcl
provider "aws" {
  region = var.vpc_region
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment_name
    }
  }
}
```
##### Explanation:

provider "aws": Specifies the AWS provider and sets the region dynamically using the vpc_region variable.

default_tags: Applies default tags to all AWS resources, aiding in resource management and cost allocation.

#### 📄 variables.tf
```hcl
variable "project_name" {
    description = "Name of the Project"
    type = string
    }
variable "environment_name" {
    description = "Name of the Project Environment"
    type = string
    }
variable "vpc_region" {
    description = "region of the VPC"
    type = string
    }
variable "cidr_block" {
    description = "cidr_block of the VPC"
    type = string
    }
variable "nat_enable" {
    description = "Nat gateway enabling"
    type  = bool
    }
variable "ami_ids" {
    description = "id of ami used"
    type  = string
    }
variable "instance_types" {
    description = "type of the instance used"
    type  = string
}
variable "host_name" {
    description = "host name used"
    type  = string
}
variable "domain_name" {
    description = "domain name used"
    type  = string
}
variable "lb_ingressports" {
    description = "ingress ports used for LB"
    type  = list
}
variable "asg_values" {
    description = "min,max and desired capacity values for AutoScaling Group"
    type  = map
}
variable "asg_enable_healthcheck" {
    description = "to enable healthcheck from LB or not"
    type  = bool
}
variable "tggrp_healthcheck" {
    description = "health check values for targetgroup"
    type = map
    
}
variable "asg_preferences" {
    description = "preferences in asg"
    type = map
}
```
##### Explanation:

Defines all the variables used throughout the Terraform configurations, allowing for flexible and reusable code.

#### 📄 production.tfvars

```hcl
project_name     = "Qreda"
environment_name = "Production"
vpc_region       = "us-east-2"
cidr_block       = "172.18.0.0/16"
ami_ids          = "ami-058a8a5ab36292159"
nat_enable       = "true"
instance_types   = "t2.micro"
host_name        = "food"
domain_name      = "freshfromhome.space"
lb_ingressports = ["80","443"]
asg_values       = {
    min_val = 2
    max_val = 4
    desrd_val = 2
    hlthchk_grace_period = 120
}
tggrp_healthcheck = {
    hlthy_thrshld = 2
    unhlthy_thrshld = 2
    intrvl = 20
    tmout  = 5
    statuscode = "200"
    paths = "/health.html"
    protocol = "HTTP"
}
asg_preferences = {
    min_hlthy_prcnt = 50
    instnc_wrmup = 120    
}
asg_enable_healthcheck = false
```

##### Explanation:

Provides specific values for the variables defined in variables.tf, tailored for the production environment.
#### 📄datasource.tf
```hcl
data "aws_availability_zones" "available_zones" {
  state = "available"
}

data "aws_route53_zone" "mydomainzone_details" {
  name         = var.domain_name
  private_zone = false
}

data "aws_ami" "qreda_ami" {
  most_recent      = true
  owners           = ["self"]

  filter {
    name   = "name"
    values = ["qreda-production-*"]
  }

  filter {
    name   = "tag:Project"
    values = [var.project_name]
  }

  filter {
    name   = "tag:Environment"
    values = [var.environment_name]
  }
}

data "aws_acm_certificate" "ssl_cert" {
  domain      = "*.${var.domain_name}"
  types       = ["AMAZON_ISSUED"]
  most_recent = true
}
```
##### Explanation:

aws_availability_zones: Retrieves a list of available availability zones in the specified region.

aws_route53_zone: Fetches details of the Route 53 hosted zone for the given domain.

aws_ami: Obtains the most recent AMI that matches the specified filters. This AMI is used in the Auto Scaling Group.

aws_acm_certificate: Retrieves the most recent ACM certificate for the domain, used for HTTPS in the Load Balancer.

#### 📄 main.tf
```hcl
resource "aws_vpc" "vpc_trfm_prjct" {
  cidr_block           = var.cidr_block
  instance_tenancy     = "default"
  enable_dns_hostnames = true

  tags = {
    Name = "VPC-${var.project_name}--${var.environment_name}"
  }
}
resource "aws_internet_gateway" "qreda_igw" {
  vpc_id = aws_vpc.vpc_trfm_prjct.id
  
  tags = {
    Name = "IGW-${var.project_name}--${var.environment_name}"
  }
}
resource "aws_subnet" "public_subnets" {
  count = 3  
  vpc_id     = aws_vpc.vpc_trfm_prjct.id
  cidr_block = cidrsubnet(var.cidr_block, 4, count.index)
  map_public_ip_on_launch = true
  availability_zone = data.aws_availability_zones.available_zones.names[count.index]
  tags = {
    Name = "Pub_Subnet_${count.index+1}-${var.project_name}--${var.environment_name}"
  }
}

resource "aws_subnet" "private_subnets" {
    count = 3
  vpc_id     = aws_vpc.vpc_trfm_prjct.id
  cidr_block = cidrsubnet(var.cidr_block, 4, count.index+3)
  availability_zone = data.aws_availability_zones.available_zones.names[count.index]
  tags = {
    Name = "Pvt__Subnet_${count.index+4}-${var.project_name}--${var.environment_name}"
  }
}

resource "aws_route_table" "pub_route" {
  vpc_id = aws_vpc.vpc_trfm_prjct.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.qreda_igw.id
  }

  tags = {
    Name = "Pub_route-${var.project_name}--${var.environment_name}"
  }
}


resource "aws_route_table_association" "pub_sub_route-association" {
  count = 3
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.pub_route.id
}

resource "aws_eip" "ElasticIP_Nat" {
  count = var.nat_enable == true ? 1 : 0
  domain = "vpc"
  tags = {
    Name = "ElasticIP_Nat-${var.project_name}--${var.environment_name}"
  }
}

resource "aws_nat_gateway" "Qreda_Nat_Gateway" {
  count = var.nat_enable == true ? 1 : 0
  allocation_id = aws_eip.ElasticIP_Nat[0].id
  subnet_id     = aws_subnet.public_subnets[1].id

  tags = {
    Name = "Qreda_Nat_Gateway-${var.project_name}--${var.environment_name}"
  }
  depends_on = [aws_internet_gateway.qreda_igw]
}

resource "aws_route_table" "pvt_route_table" {    
 vpc_id = aws_vpc.vpc_trfm_prjct.id
 tags = {
    Name = "Pvt_route-table-${var.project_name}--${var.environment_name}"
  }
}

resource "aws_route" "pvt_route" {
   count = var.nat_enable == true ? 1 : 0
   destination_cidr_block     = "0.0.0.0/0"
    route_table_id = aws_route_table.pvt_route_table.id
    nat_gateway_id = aws_nat_gateway.Qreda_Nat_Gateway[0].id
  }



resource "aws_route_table_association" "pvt_sub_route-association" {
    count = 3
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.pvt_route_table.id
}


```
##### Explanation:
VPC Creation
Defines a VPC with a customizable CIDR block (var.cidr_block). It enables DNS hostnames and sets a meaningful name tag using the project and environment variables.

Internet Gateway (IGW)
Creates an Internet Gateway attached to the VPC, allowing public internet access for resources in public subnets.

Public Subnets
Creates 3 public subnets (using count = 3) across different availability zones for high availability and fault tolerance. Each subnet gets a unique CIDR block derived from the main VPC CIDR and is tagged appropriately. Public subnets are configured to assign public IPs to launched instances automatically.

Private Subnets
Creates 3 private subnets similarly distributed across availability zones, each with its own CIDR block offset from the VPC CIDR. Private subnets do not assign public IPs and are tagged for identification.

Public Route Table
Creates a route table for the public subnets with a default route (0.0.0.0/0) pointing to the Internet Gateway. This enables outbound internet access for instances in public subnets.

Public Route Table Associations
Associates each public subnet with the public route table to apply the internet access routing rules.

Elastic IP for NAT Gateway (Conditional)
Allocates an Elastic IP for the NAT Gateway, only if var.nat_enable is true. This EIP allows the NAT Gateway to have a fixed public IP address.

NAT Gateway (Conditional)
Creates a NAT Gateway in one of the public subnets (specifically the second one, index 1). The NAT Gateway allows private subnet instances to access the internet securely (for updates, patches, etc.) without exposing them directly. This resource is only created if var.nat_enable is true.

Private Route Table
Creates a dedicated route table for the private subnets.

Private Route (Conditional)
Adds a default route (0.0.0.0/0) in the private route table to forward internet-bound traffic to the NAT Gateway, allowing outbound internet access from private subnets while keeping them secure. This is conditional on NAT Gateway being enabled.

Private Route Table Associations
Associates each private subnet with the private route table, ensuring they use the NAT Gateway for internet access if enabled.

Notes:

The use of 3 public and 3 private subnets distributes resources across multiple availability zones, providing redundancy and fault tolerance in case of an AZ failure.

NAT Gateway is optional and controlled by var.nat_enable. This is a best practice for cost-saving and flexibility.

#### 📄 instances.tf
```hcl
resource "aws_key_pair" "qreda_key1" {
  key_name   = "qreda_key1"
  public_key = file("erpkeypair1.pub")
tags = {
    Name = "key1-${var.project_name}--${var.environment_name}"
    Project = var.project_name
    Environment = var.environment_name
  }
}

resource "aws_security_group" "bastion_SG" {
  name   = "bastion_SG-${var.project_name}--${var.environment_name}"
  vpc_id = aws_vpc.vpc_trfm_prjct.id
egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
tags = {
    Name = "bastion_SG-${var.project_name}--${var.environment_name}"
    Project = var.project_name
    Environment = var.environment_name
  }
}
resource "aws_security_group_rule" "bastionSG_ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.bastion_SG.id

}


resource "aws_security_group" "LB_SG" {
  name   = "LB_SG-${var.project_name}--${var.environment_name}"
  vpc_id = aws_vpc.vpc_trfm_prjct.id
egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
tags = {
    Name = "LB_SG-${var.project_name}--${var.environment_name}"
    Project = var.project_name
    Environment = var.environment_name
  }
}
resource "aws_security_group_rule" "LB_SG_ingress" {
  for_each           = toset(var.lb_ingressports)
  type              = "ingress"
  from_port         = each.key
  to_port           = each.key
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.LB_SG.id

}


resource "aws_security_group" "Instances_SG" {
  name   = "Instances_SG-${var.project_name}--${var.environment_name}"
  vpc_id = aws_vpc.vpc_trfm_prjct.id
egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
tags = {
    Name = "Instances_SG-${var.project_name}--${var.environment_name}"
    Project = var.project_name
    Environment = var.environment_name
  }
}
resource "aws_security_group_rule" "Instances_SG_ingress_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  security_group_id = aws_security_group.Instances_SG.id
  source_security_group_id = aws_security_group.LB_SG.id
}
resource "aws_security_group_rule" "Instances_SG_ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = aws_security_group.Instances_SG.id
  source_security_group_id = aws_security_group.bastion_SG.id
}
```

##### Explanation
This file defines EC2 instances, including the Bastion host and the launch template for the Auto Scaling Group.
#### 📄 bastion.tf (Jump Box)

```hcl
resource "aws_instance" "qreda_bastionInstance" {
    ami = var.ami_ids
    instance_type = var.instance_types
    key_name = aws_key_pair.qreda_key1.id
    subnet_id = aws_subnet.public_subnets[1].id
    vpc_security_group_ids = [aws_security_group.bastion_SG.id]
tags = {
    Name = "Bastioninstance-${var.project_name}--${var.environment_name}"
    Project = var.project_name
    Environment = var.environment_name
  }
}
```
##### Explanation
aws_instance.bastion: Launches a lightweight public EC2 instance to act as a secure SSH gateway to reach private instances.

ami: The Amazon Machine Image used for the instance.

subnet_id: Placed in the first public subnet.

vpc_security_group_ids: Associates the bastion-specific security group.

key_name: The SSH key to access the instance.

associate_public_ip_address: Ensures the instance has a public IP for remote access.

#### 📄launchtemplate.tf  (Launch Template for EC2 Instances - Used in Auto Scaling Group)
```hcl
resource "aws_launch_template" "qreda_launch_template" {
    name = "launch_template-${var.project_name}-${var.environment_name}"
    description = "launch_template for -${var.project_name}-${var.environment_name}"
    image_id = data.aws_ami.qreda_ami.image_id
    instance_type = var.instance_types
    key_name = aws_key_pair.qreda_key1.id
    vpc_security_group_ids = [aws_security_group.Instances_SG.id]
}
```
##### Explanation
aws_launch_template: Creates a template for launching EC2 instances in the ASG.

name_prefix: Automatically appends a unique suffix.

image_id: The AMI ID for the app server.

vpc_security_group_ids: Links to the application security group.

tag_specifications: Tags the EC2 instance for easier management.

#### 📄autoscaling.tf 
   ```hcl
resource "aws_autoscaling_group" "qreda_ASG" {
  name                      = "ASG-${var.project_name}-${var.environment_name}"
  max_size                  = var.asg_values["max_val"]
  min_size                  = var.asg_values["min_val"]
  desired_capacity          = var.asg_values["desrd_val"]
  health_check_grace_period = var.asg_values["hlthchk_grace_period"]
  health_check_type         = var.asg_enable_healthcheck ? "ELB" : "EC2"
  vpc_zone_identifier       = aws_subnet.private_subnets[*].id
   
  tag {
    key                 = "Name"
    value               = "ASG-${var.project_name}-${var.environment_name}"
    propagate_at_launch = true
  }
launch_template {
    id      = aws_launch_template.qreda_launch_template.id
    version = aws_launch_template.qreda_launch_template.latest_version
  }
instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = var.asg_preferences["min_hlthy_prcnt"]
      instance_warmup = var.asg_preferences["instnc_wrmup"]
    }
}
}
``` 
##### Explanation
desired_capacity, min_size, max_size: Controls how many instances are maintained.

vpc_zone_identifier: ASG launches instances in the specified subnet (private).

launch_template: Uses the EC2 launch template defined earlier.

target_group_arns: Registers EC2 instances with the ALB.

health_check_type: Ensures only healthy instances are used.

#### 📄 lb.tf 
```hcl
resource "aws_lb_target_group" "qreda_LB_targetgrp" {
  name     = "LB-targetgrp-${var.project_name}-${var.environment_name}"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc_trfm_prjct.id
  deregistration_delay = 10
  health_check {
    healthy_threshold = var.tggrp_healthcheck["hlthy_thrshld"]
    unhealthy_threshold = var.tggrp_healthcheck["unhlthy_thrshld"]
    interval = var.tggrp_healthcheck["intrvl"]
    timeout = var.tggrp_healthcheck["tmout"]
    matcher = var.tggrp_healthcheck["statuscode"]
    path = var.tggrp_healthcheck["paths"]
    protocol = var.tggrp_healthcheck["protocol"]
    
}
}

resource "aws_autoscaling_attachment" "qreda_ASG_LB_targetinstances" {
  autoscaling_group_name = aws_autoscaling_group.qreda_ASG.id
  lb_target_group_arn    = aws_lb_target_group.qreda_LB_targetgrp.arn
}

resource "aws_lb" "qreda_LB" {
  name               = "LB-${var.project_name}-${var.environment_name}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.LB_SG.id]
  subnets            = aws_subnet.public_subnets[*].id

  enable_deletion_protection = false
  tags = {
   Project = var.project_name
    Environment = var.environment_name
  }
}
resource "aws_lb_listener" "qreda_LB_listener_https" {
  load_balancer_arn = aws_lb.qreda_LB.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.ssl_cert.arn
    default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qreda_LB_targetgrp.arn
  }
}
resource "aws_lb_listener" "qreda_LB_listener_http" {
  load_balancer_arn = aws_lb.qreda_LB.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
```
##### Explanation
aws_lb: Creates an internet-facing Application Load Balancer.

internal = false: Makes the ALB publicly accessible.

subnets: Deploys ALB in multiple public subnets for high availability.

security_groups: Restricts/controls incoming traffic using ALB security group.

aws_lb_target_group: Defines where the ALB will route traffic.

health_check: Monitors instance health and removes unhealthy targets.

aws_lb_listener: Listens for incoming HTTP traffic on port 80.

default_action: Forwards the traffic to the defined target group.

#### 📄 route53.tf (Optional)
```hcl
resource "aws_route53_record" "mydomain" {
  zone_id = data.aws_route53_zone.mydomainzone_details.zone_id
  name    = "${var.host_name}.${var.domain_name}"
  type    = "A"
  alias {
    name                   = aws_lb.qreda_LB.dns_name
    zone_id                = aws_lb.qreda_LB.zone_id
    evaluate_target_health = true
  }
}
```
##### Explanation
aws_route53_record: Points your domain to the ALB DNS.

alias block: Required for mapping to an AWS-managed resource like ALB.

#### 📄 output.tf
```hcl
output "qreda_lb_public_dns" {
   value = aws_lb.qreda_LB.dns_name
}

output "qreda_lb_http_url" {
   value = "http://${var.host_name}.${var.domain_name}"
}

output "qreda_lb_https_url" {
  value = "https:///${var.host_name}.${var.domain_name}:"
}
```
##### Explanation
These outputs are helpful for verification, SSH access, and DNS registration post-deployment.

## ⚠️ Terraform Destroy Warning for Beginners
#### ⚠️ WARNING: Be Careful with terraform destroy

Running terraform destroy will permanently delete all the infrastructure you've provisioned with Terraform. This includes:

EC2 instances

VPC and subnets

Load balancers

NAT Gateways

Security Groups

Any resources managed by your Terraform scripts

#### ⚠️ Best Practices Before Destroying:

Double-check your workspace and AWS account.

Backup any important data from EC2, RDS, or other services.

Confirm that no one else is using the environment.

Run terraform plan -destroy to preview what will be removed.

Consider using terraform taint or terraform state rm for selective destruction.
