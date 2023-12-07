#! /usr/bin/env python3

import argparse
from log_record import Logger
from csmdeployer import Csmdeployer

# kubernetes 集群预配置
def kubernetes(csm):
    if csm.configure_kubectl_tool():
        print("配置 kubectl 工具完成")
    if csm.configure_net():
        print("配置网络完成")
    if csm.configure_controller():
        print("配置 controller 节点完成")
    if csm.configure_storageclass():
        print("配置默认 storageclass 完成")

# 初始化 CoSAN Manager
def initialising_cosan_manager(csm):
    if csm.initialising_cosan_manager():
        print("初始化完成")
    csm.default_execution()
    print("默认镜像替换完成")

# 更改 image
def exchange_image(csm):
    if csm.update_images_from_config():
        print("更新 image 完成")

# 部署 LINSTOR CSI
def deploy_linstaor_csi(csm):
    if csm.configure_linstor_csi():
        print("部署 LINSTOR CSI 完成")
    if csm.create_storageclass():
        print("创建 StorageClass 完成")
    if csm.create_pvc_of_iscsi():
        print("创建 iSCSI 功能用到的 pvc 完成")

# 配置分布式存储节点
def configure_distributed_storage_nodes(csm):
    if csm.configure_linstor_controller_configMap():
        print("配置 LINSTOR Controller ConfigMap 完成")
    if csm.configure_ks_apiserver():
        print("配置 ks-apiserver 完成")

def display_version():
    print("version: v1.0.0")

def main():
    parser = argparse.ArgumentParser(description='csmdeployer')
    parser.add_argument('-i', '--initialise', action='store_true',
                        help='initialising CoSAN Manager')
    parser.add_argument('-k', '--kubernetes', action='store_true',
                        help='Deploying kubernetes cluster preconfiguration')
    parser.add_argument('-c', '--configure', action='store_true',
                        help='configuring distributed storage nodes')
    parser.add_argument('-e', '--exchange', action='store_true',
                        help='exchange image')
    parser.add_argument('-d', '--deploy', action='store_true',
                        help='deploy linstaor csi')
    parser.add_argument('-v', '--version', action='store_true',
                        help='Show version information')
    args = parser.parse_args()

    logger = Logger("csmdeployer")
    csm = Csmdeployer(logger)
    
    if args.exchange: 
        exchange_image(csm) 
    elif args.version:
        display_version()
    else:
        kubernetes(csm)
        initialising_cosan_manager(csm)
        deploy_linstaor_csi(csm)
        configure_distributed_storage_nodes(csm)

if __name__ == '__main__':
    main()