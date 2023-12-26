variable "instance_name" {
  description = "Value of the Name tag for the EC2 instance"
  type        = string
  default     = "ExampleAppServerInstance"
}
variable "azs" {
  description = "AZs that the NAT gateways will be deployed"
  type        = list(string)
  default     = ["us-east-1a","us-east-1b"]
}
variable "region"{
  description = "region to create resources"
  type        = string
  default     = "us-east-1"
}
variable "domain_name" {
  description = "The domain name for which the certificate should be issued"
  type        = string
  default     = "ace-test"
}
variable "target_id" {
  description = "The id of the ec2 instances"
  type        = any
  default     = {}
}
