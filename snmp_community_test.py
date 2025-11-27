import argparse
import asyncio
import ipaddress
import pandas as pd
import warnings
from pysnmp.hlapi.v3arch.asyncio import get_cmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity

warnings.filterwarnings('ignore')

async def test_snmp_community(ip, community, port=161, timeout=5):
    """
    测试单个IP和团体字的组合
    
    Args:
        ip (str): 目标IP地址
        community (str): SNMP团体字
        port (int): SNMP端口，默认为161
        timeout (int): 超时时间(秒)
    
    Returns:
        dict: 包含测试结果的字典
    """
    # 尝试获取系统描述符
    transport_target = await UdpTransportTarget.create((ip, port), timeout)
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        SnmpEngine(),
        CommunityData(community),
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
    )
    
    result = {
        'ip': ip,
        'port': port,
        'community': community,
        'status': 'failed',
        'error': '',
        'sys_descr': ''
    }
    
    if errorIndication:
        result['error'] = str(errorIndication)
    elif errorStatus:
        result['error'] = f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}'
    else:
        result['status'] = 'success'
        result['sys_descr'] = str(varBinds[0][1])
        
    return result

async def batch_test_snmp(ip_list, community_list, port=161, timeout=5):
    """
    批量测试SNMP团体字
    
    Args:
        ip_list (list): IP地址列表
        community_list (list): 团体字列表
        port (int): SNMP端口
        timeout (int): 超时时间
    
    Returns:
        list: 测试结果列表
    """
    results = []
    
    for ip in ip_list:
        for community in community_list:
            print(f"Testing {ip} with community '{community}'...")
            result = await test_snmp_community(ip, community, port, timeout)
            results.append(result)
            
    return results

def load_from_file(file_path):
    """
    从文件加载列表数据
    
    Args:
        file_path (str): 文件路径
    
    Returns:
        list: 去除空行和注释的内容列表
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
        return lines
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

def save_to_xlsx(results, output_file):
    """
    将结果保存到xlsx文件
    
    Args:
        results (list): 测试结果列表
        output_file (str): 输出文件路径
    """
    df = pd.DataFrame(results)
    df.to_excel(output_file, index=False)
    print(f"Results saved to {output_file}")

def validate_ip(ip):
    """
    验证IP地址格式是否正确
    
    Args:
        ip (str): IP地址字符串
    
    Returns:
        bool: 是否为有效IP地址
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(description='批量测试SNMP团体字')
    parser.add_argument('-i', '--ips', help='目标IP地址列表，用逗号分隔或指定包含IP列表的文件')
    parser.add_argument('-c', '--communities', help='团体字列表，用逗号分隔或指定包含团体字列表的文件')
    parser.add_argument('-p', '--port', type=int, default=161, help='SNMP端口 (默认: 161)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='超时时间(秒) (默认: 5)')
    parser.add_argument('-o', '--output', default='snmp_results.xlsx', help='输出文件路径 (默认: snmp_results.xlsx)')
    parser.add_argument('--default-communities', action='store_true', help='使用默认团体字列表')
    
    args = parser.parse_args()
    
    # 默认团体字列表
    default_communities = [
        'public', 'private', 'community', 'test', 'admin', 'root',
        'snmp', 'monitor', 'read', 'write', 'access', 'default'
    ]
    
    # 处理IP列表
    if args.ips:
        if args.ips.endswith('.txt'):
            ip_list = load_from_file(args.ips)
        else:
            ip_list = [ip.strip() for ip in args.ips.split(',') if ip.strip()]
        
        # 验证IP地址
        valid_ips = []
        for ip in ip_list:
            if validate_ip(ip):
                valid_ips.append(ip)
            else:
                print(f"Invalid IP address: {ip}, skipping...")
        ip_list = valid_ips
    else:
        print("请提供目标IP地址列表 (-i/--ips)")
        return
    
    # 处理团体字列表
    if args.default_communities:
        community_list = default_communities
    elif args.communities:
        if args.communities.endswith('.txt'):
            community_list = load_from_file(args.communities)
        else:
            community_list = [comm.strip() for comm in args.communities.split(',') if comm.strip()]
    else:
        print("请提供团体字列表 (-c/--communities) 或使用默认团体字 (--default-communities)")
        return
    
    if not ip_list:
        print("没有有效的IP地址进行测试")
        return
        
    if not community_list:
        print("团体字列表为空")
        return
    
    print(f"开始测试 {len(ip_list)} 个IP地址和 {len(community_list)} 个团体字的组合...")
    print(f"IP列表: {', '.join(ip_list)}")
    print(f"团体字列表: {', '.join(community_list)}")
    
    # 异步运行测试
    results = asyncio.run(batch_test_snmp(ip_list, community_list, args.port, args.timeout))
    
    # 保存结果到xlsx文件
    save_to_xlsx(results, args.output)
    
    # 显示成功的结果
    success_count = sum(1 for r in results if r['status'] == 'success')
    print(f"\n测试完成! 成功: {success_count}, 失败: {len(results) - success_count}")
    
    if success_count > 0:
        print("\n成功的连接:")
        for result in results:
            if result['status'] == 'success':
                print(f"  {result['ip']}:{result['port']} - Community: {result['community']}")

if __name__ == '__main__':
    main()