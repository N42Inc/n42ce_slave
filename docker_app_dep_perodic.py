'''
Author: Networks42
Description: Finds Dependencies between the docker containers
'''
import os,subprocess,time,re,json,redis,ast,traceback
import port_dictionary
import requests,datetime

interval=300
hostname=os.uname()[1]
base_path=os.path.dirname(os.path.abspath(__file__))
tenant_name=os.environ['key']
interface_ip_list=list()
bridges_ip=list()
local_container_data=dict()
host_dicts=dict()#{<Interface_IP>-<MAP-Port>:[ip,cid,cname,]}
docker_info=list()

headers = {'content-type': 'application/json'}
info_url="http://52.8.104.253:8161/n42-services/resources/appdiscovery/updateContainerDetails"
delete_url="http://52.8.104.253:8161/n42-services/resources/appdiscovery/deleteContainerDetails"
dependency_url="http://52.8.104.253:8161/n42-services/resources/appdiscovery/updateContainerDependency"
event_dictionary={"start":"started","stop":"stopped"}
config = {'host': '52.8.104.253', 'port': 6379, 'db': 0}
docker_path="/var/lib/docker/containers"

commands={"connections":"conntrack -L -p tcp | grep -v UNREPLIED |grep 'TIME_WAIT\|ESTABLISHED\|CLOSE'",
            "interface_ips":"ip addr | grep -w inet",
            "bridges":"brctl show",
            "bridges_ips":"ip addr show {} | grep -w inet"}

files={"tcp_stats":"/proc/net/tcp",
       "docker-info":"/var/lib/docker/containers/{}/config.v2.json",
       "containers":"/var/lib/docker/containers"}

def execuite_cmd(cmd):
    return subprocess.check_output(cmd,shell=True)

def wipe_varibles():
    global docker_info,host_dicts,local_container_data,bridges_ip,interface_ip_list
    interface_ip_list=[]
    bridges_ip=[]
    local_container_data.clear()
    host_dicts.clear()
    docker_info=[]

def merge_dicts(*dict_args):
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def set_interface_ips():
    global interface_ip_list, bridges_ip
    output1=execuite_cmd(commands["interface_ips"])
    output2=execuite_cmd(commands["bridges"])
    for line in output1.split("\n"):
        if not line or re.search(' lo', line):
            continue
        ip=line.split()[1].split("/")[0]
        interface_ip_list.append(ip)
    
    for line in output2.split("\n"):
        if not line or re.search("bridge name", line):
            continue
        parts=line.split()
        if len(parts)>2:
            try:
                output2=execuite_cmd(commands["bridges_ips"].format(parts[0]))
            except Exception:
                continue
            b_ip=output2.split()[1].split("/")[0]
            interface_ip_list.remove(b_ip)
            bridges_ip.append(b_ip)

def get_service(port_list,label):
    try:
        if label:
            return label["service"]
    except Exception:
        if port_list and  port_list[0]["actual-port"] in port_dictionary.port_dict:
            return port_dictionary.port_dict[port_list[0]["actual-port"]]
        else:
            return "unknown"

def set_docker_info():
    global interface_ip_list, host_dicts, local_container_data, docker_info
    global_container_data=dict()
    container_id=os.listdir(files["containers"])# Get the List of Container IDS
    for ids in container_id: #Iter the CID to get container details
        if ids:
            port_list=list()
            try:
                f=open(files["docker-info"].format(ids),'r')
            except Exception:
                continue
            data = json.load(f)
            if data["State"]["Running"]:
                ip_addresses=list()
                for key,value in data["NetworkSettings"]["Ports"].items():
                    ip=[data["NetworkSettings"]["Networks"][a]["IPAddress"] for a in data["NetworkSettings"]["Networks"]]
                    if not value:
                        continue
                    for ports in value:
                        if ports["HostIp"]=="0.0.0.0":
                            for ips in interface_ip_list:
                                global_container_data[ips+":"+ports["HostPort"]]={"cid":ids[:12],"port":key.split("/")[0],"cname":data["Name"].lstrip("/"),"ip":ip,"hostname":hostname}
                        else:
                            global_container_data[ports["HostIp"]+":"+ports["HostPort"]]={"cid":ids[:12],"port":key.split("/")[0],"cname":data["Name"].lstrip("/")}
                        port_list.append({"map-port":ports["HostPort"],"actual-port":key.split("/")[0]})
                for v1 in data["NetworkSettings"]["Networks"].values():
                    local_container_data[v1["IPAddress"]]=[port_list,ids[:12],data["Name"].lstrip("/")]
                    ip_addresses.append(v1["IPAddress"])
                service_name=get_service(port_list,data["Config"]["Labels"])
                docker_info.append({"cid":ids[:12],"cname":data["Name"].lstrip("/"),"hostname":hostname,"pid":data["State"]["Pid"],"ip":ip_addresses,"image":data["Config"]["Image"],"Tenant_Name":tenant_name,"labels":data["Config"]["Labels"],"service":service_name})
    json_data=json.dumps(docker_info)              
    try:
        r = redis.StrictRedis(**config)
    except Exception:
        print "*****Connection problem at REDIS. Will try in 30 sec!"
        time.sleep(30)
        raise Exception
    r.hset(tenant_name+"-info",hostname,global_container_data)
    time.sleep(3)
    cluster_info=r.hgetall(tenant_name+"-info")
    for x in cluster_info.values():
        host_dicts.update(ast.literal_eval(x))
    print "=================== Docker Info ===================\n"
    print json_data
    response = requests.post(info_url, data=json_data,headers=headers)
    print response,"\n"
  
def parse_contrack():
    global host_dicts,local_container_data
    neighbors=set()
    file=execuite_cmd(commands["connections"])
    for line in file.split("\n"):
        if line and "127.0.0.1" not in line and "tcp" in line:
            line_list= line.split()
            src_ip1=line_list[4].split("=")[1]
            dst_ip1=line_list[5].split("=")[1]
            #src_port1=line_list[6].split("=")[1]
            dst_port1=line_list[7].split("=")[1]
            
            src_ip2=line_list[8].split("=")[1]
            dst_ip2=line_list[9].split("=")[1]
            #src_port2=line_list[10].split("=")[1]
            #dst_port2=line_list[11].split("=")[1]
            if src_ip1 in bridges_ip and dst_ip2 in bridges_ip:
                continue #Packets coming from docker0(Default Gateway)
            elif dst_ip1+":"+dst_port1 in host_dicts and src_ip1 in local_container_data:
                if src_ip1 in local_container_data and dst_ip1+":"+dst_port1 in host_dicts:
                    src_con=local_container_data[src_ip1][1]
                    dst_con=host_dicts[dst_ip1+":"+dst_port1]["cid"]
                    port=host_dicts[dst_ip1+":"+dst_port1]["port"]
                    if port in port_dictionary.port_dict:
                        service=port_dictionary.port_dict[port]
                    else:
                        service="Unknown:{0}".format(port)
                    neighbors.add(src_con+"-"+dst_con+"-"+service)         
            
            elif src_ip1 in local_container_data and dst_ip1 in local_container_data:
                if src_ip1 in local_container_data and dst_ip1 in local_container_data:
                    src_con=local_container_data[src_ip1][1]
                    dst_con=local_container_data[dst_ip1][1]
                    if dst_port1 in port_dictionary.port_dict:
                        service=port_dictionary.port_dict[dst_port1]
                    else:
                        service="Unknown:{0}".format(port)
                    neighbors.add(src_con+"-"+dst_con+"-"+service)
            elif dst_ip1+":"+dst_port1 in host_dicts and src_ip1 not in local_container_data:
                if src_ip2 in local_container_data:
                    src_con="UNKNOWN"
                    dst_con=host_dicts[dst_ip1+":"+dst_port1]["cid"]
                    port=host_dicts[dst_ip1+":"+dst_port1]["port"]
                    if port in port_dictionary.port_dict:
                        service=port_dictionary.port_dict[port]
                    else:
                        service="Unknown:{0}".format(port)
                    neighbors.add(src_con+"-"+dst_con+"-"+service)
                           
    dependency=list()
    for key in neighbors:
        part=key.split("-")
        data={"srcvm":part[0],
              "dstvm":part[1],
              "dstservice":part[2],
              "srctenant":tenant_name,
              "dsttenant":tenant_name}
        dependency.append(data)
    print "=================== Docker Dependencies ===================\n"
    if not dependency:
        json_data=json.dumps([{"tenant":tenant_name}])
        print "No Traffic Found!"
    else:
        json_data=json.dumps(dependency)
    print json_data
    try:
        response = requests.post(dependency_url, data=json_data,headers=headers)
    except Exception:
        print "*****Connection Problem at REST API. Will retry in 30 Sec"
        time.sleep(30)
        raise Exception
    print response
    
                  
while True:
    try:
        set_interface_ips()
        set_docker_info()
        parse_contrack()
        wipe_varibles()
        print "Completed at",datetime.datetime.now()
        time.sleep(interval)
    except Exception:
        print "================ Something Went Wrong. TRACEBACK BELOW ================\n"
        print traceback.format_exc()
        print "\nTIMESTAMP",datetime.datetime.now(),"\n"
        continue


