import os
from collections import defaultdict
from datetime import datetime
from typing import Optional

import pymongo
import pymongo.response
from bson.objectid import ObjectId
from flask_pymongo import PyMongo
from oakestra_utils.types.statuses import (
    DeploymentStatus,
    LegacyStatus,
    NegativeSchedulingStatus,
    PositiveSchedulingStatus,
    Status,
    convert_to_status,
)

MONGO_URL = os.environ.get("CLUSTER_MONGO_URL")
MONGO_PORT = os.environ.get("CLUSTER_MONGO_PORT")

MONGO_ADDR_NODES = "mongodb://" + str(MONGO_URL) + ":" + str(MONGO_PORT) + "/nodes"
MONGO_ADDR_JOBS = "mongodb://" + str(MONGO_URL) + ":" + str(MONGO_PORT) + "/jobs"

mongo_nodes = None
mongo_jobs = None
app = None


def mongo_init(flask_app):
    global app
    global mongo_nodes, mongo_jobs

    app = flask_app

    mongo_nodes = PyMongo(app, uri=MONGO_ADDR_NODES)
    mongo_jobs = PyMongo(app, uri=MONGO_ADDR_JOBS)

    app.logger.info("MONGODB - init mongo")


# ................. Worker Node Operations ...............#
###########################################################


def mongo_upsert_node(obj):
    global app, mongo_nodes
    app.logger.info("MONGODB - upserting node...")
    json_node_info = obj["node_info"]
    node_info_hostname = json_node_info.get("host")

    nodes = mongo_nodes.db.nodes
    # find node by hostname and if it exists, just upsert
    node_id = nodes.find_one_and_update(
        {"node_info.host": node_info_hostname},
        {
            "$set": {
                "node_info": json_node_info,
                "node_address": obj.get("ip"),
                "node_subnet": obj.get("node_subnet"),
            }
        },
        upsert=True,
        return_document=True,
    ).get("_id")
    app.logger.info(node_id)
    return node_id


def mongo_find_node_by_id(node_id):
    global mongo_nodes
    return mongo_nodes.db.nodes.find_one(node_id)


def mongo_find_node_by_name(node_name):
    global mongo_nodes
    try:
        return mongo_nodes.db.nodes.find_one({"node_info.host": node_name})
    except Exception:
        return "Error"


def mongo_find_node_by_id_and_update_cpu_mem(node_id, node_payload):
    global app, mongo_nodes
    app.logger.info("MONGODB - update cpu and memory of worker node {0} ...".format(node_id))
    # o = mongo.db.nodes.find_one({'_id': node_id})
    # print(o)

    time_now = datetime.now()

    mongo_nodes.db.nodes.find_one_and_update(
        {"_id": ObjectId(node_id)},
        {
            "$set": {
                "current_cpu_percent": node_payload.get("cpu", 0),
                "current_cpu_cores_free": node_payload.get("free_cores", 0),
                "current_memory_percent": node_payload.get("memory", 0),
                "current_free_memory_in_MB": node_payload.get("memory_free_in_MB", 0),
                "gpu_driver": node_payload.get("gpu_driver", "-"),
                "gpu_usage": node_payload.get("gpu_usage", 0),
                "gpu_cores": node_payload.get("gpu_cores", 0),
                "gpu_temp": node_payload.get("gpu_temp", 0),
                "gpu_mem_used": node_payload.get("gpu_mem_used", 0),
                "gpu_tot_mem": node_payload.get("gpu_tot_mem", 0),
                "last_modified": time_now,
                "last_modified_timestamp": datetime.timestamp(time_now),
            }
        },
        upsert=True,
    )

    return 1


def find_one_edge_node():
    """Find first occurrence of edge nodes"""
    global mongo_nodes
    return mongo_nodes.db.nodes.find_one()


def find_all_nodes():
    global mongo_nodes
    return mongo_nodes.db.nodes.find()


def mongo_dead_nodes():
    print("looking for dead nodes")


def mongo_aggregate_node_information(TIME_INTERVAL):
    """1. Find all nodes"""
    """ 2. Aggregate cpu, memory, and more information of worker nodes"""

    global mongo_nodes

    cumulative_values = {
        "cpu_percent": 0,
        "cpu_cores": 0,
        "memory_percent": 0,
        "gpu_tot_mem": 0,
        "gpu_mem_used": 0,
        "gpu_temp": 0,
        "gpu_drivers": [],
        "gpu_percent": 0,
        "gpu_cores": 0,
        "cumulative_memory_in_mb": 0,
        "number_of_nodes": 0,
    }

    technology = set()
    supported_addons = set()
    aggregation_per_architecture = defaultdict(
        lambda: {"cpu_percent": 0, "cpu_cores": 0, "memory": 0, "memory_in_mb": 0}
    )

    nodes = find_all_nodes()
    for n in nodes:
        try:
            if n.get("last_modified_timestamp") < (datetime.now().timestamp() - TIME_INTERVAL):
                print("Node {0} is inactive.".format(n.get("_id")))
                continue

            node_info = n.get("node_info")

            # if it is not older than TIME_INTERVAL
            cumulative_values["cpu_percent"] += n.get("current_cpu_percent", 0)
            cumulative_values["cpu_cores"] += n.get("current_cpu_cores_free", 0)
            cumulative_values["memory_percent"] += n.get("current_memory_percent", 0)
            cumulative_values["gpu_tot_mem"] += n.get("gpu_tot_mem", 0)
            cumulative_values["gpu_mem_used"] += n.get("gpu_mem_used", 0)
            cumulative_values["gpu_temp"] += n.get("gpu_temp", 0)
            cumulative_values["gpu_drivers"].append(n.get("gpu_driver", "-"))
            cumulative_values["cumulative_memory_in_mb"] += n.get("current_free_memory_in_MB", 0)
            cumulative_values["gpu_percent"] += n.get("gpu_usage", 0)
            cumulative_values["gpu_cores"] += n.get("gpu_cores", 0)
            cumulative_values["number_of_nodes"] += 1

            technology.update(node_info.get("technology", []))
            supported_addons.update(node_info.get("supported_addons", []))

            arch = node_info.get("architecture")
            aggregation = aggregation_per_architecture[arch]
            aggregation["cpu_percent"] += n.get("current_cpu_percent", 0)
            aggregation["cpu_cores"] += n.get("current_cpu_cores_free", 0)
            aggregation["memory"] += n.get("current_memory_percent", 0)
            aggregation["memory_in_mb"] += n.get("current_free_memory_in_MB", 0)
            # GPU not aggregated for unikernel

        except Exception as e:
            print(
                "Problem during the aggregation of the data, skipping the node: ",
                str(n),
                " - because - ",
                str(e),
            )

    mongo_update_jobs_status(TIME_INTERVAL)
    jobs = mongo_find_all_jobs()

    return {
        **cumulative_values,
        "jobs": jobs,
        "virtualization": list(technology),
        "aggregation_per_architecture": dict(aggregation_per_architecture),
        "more": 0,
        "supported_addons": list(supported_addons),
    }


# ................. Job Operations .......................#
###########################################################


def mongo_create_new_job_instance(job: dict, system_job_id: str, instance_number: int) -> dict:
    print("insert/upsert requested job")
    job["system_job_id"] = system_job_id
    del job["_id"]
    if job.get("instance_list") is not None:
        del job["instance_list"]
    result = mongo_jobs.db.jobs.find_one_and_update(
        {"system_job_id": str(job["system_job_id"])},
        {"$set": job},
        upsert=True,
        return_document=True,
    )  # if job does not exist, insert it
    if result.get("instance_list") is None:
        result["instance_list"] = []
    result["instance_list"].append(
        {
            "instance_number": instance_number,
            "status": PositiveSchedulingStatus.CLUSTER_SCHEDULED.value,
        }
    )
    mongo_jobs.db.jobs.find_one_and_update(
        {"system_job_id": str(job["system_job_id"])},
        {"$set": {"instance_list": result["instance_list"]}},
    )
    result["_id"] = str(result["_id"])
    return result


def mongo_find_job_by_system_id(system_job_id):
    return mongo_jobs.db.jobs.find_one({"system_job_id": str(system_job_id)})


def mongo_find_job_by_id(id):
    print("Find job by Id")
    return mongo_jobs.db.jobs.find_one({"_id": ObjectId(id)})


def mongo_update_jobs_status(time_interval: int) -> None:
    """Marks inactive jobs as failed.

    If there are no updates from a job in the last TIME_INTERVAL mark it as failed,
    unless the job is completed.
    """
    jobs = mongo_find_all_jobs()
    for job in jobs:
        try:
            updated = False
            for instance in range(len(job["instance_list"])):
                last_time_job_was_modified = job["instance_list"][instance].get(
                    "last_modified_timestamp", datetime.now().timestamp()
                )
                job_is_inactive = last_time_job_was_modified < (
                    datetime.now().timestamp() - time_interval
                )
                job_status = (
                    convert_to_status(job["instance_list"][instance].get("status"))
                    or LegacyStatus.LEGACY_0
                )
                if (
                    job_is_inactive
                    and job_status not in PositiveSchedulingStatus
                    and job_status != DeploymentStatus.COMPLETED
                ):
                    print("Job is inactive: " + str(job.get("job_name")))
                    new_job_status = DeploymentStatus.FAILED
                    job["instance_list"][instance]["status"] = new_job_status.value
                    updated = True
            if updated:
                mongo_jobs.db.jobs.update_one(
                    {"system_job_id": str(job["system_job_id"])},
                    {
                        "$set": {
                            "instance_list": job["instance_list"],
                            "status": new_job_status.value,
                        }
                    },
                )
        except Exception as e:
            print(e)


def mongo_find_all_jobs():
    global mongo_jobs
    # list (= going into RAM) okey for small result sets (not clean for large data sets!)
    return list(
        mongo_jobs.db.jobs.find(
            {},
            {
                "_id": 0,
                "system_job_id": 1,
                "job_name": 1,
                "status": int(LegacyStatus.LEGACY_1.value),
                "instance_list": 1,
            },
        )
    )


def mongo_find_job_by_name(job_name):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one({"job_name": job_name})


def mongo_find_job_by_ip(ip):
    global mongo_jobs
    # Search by Service Ip
    job = mongo_jobs.db.jobs.find_one({"service_ip_list.Address": ip})
    if job is None:
        # Search by instance ip
        job = mongo_jobs.db.jobs.find_one({"instance_list.instance_ip": ip})
    return job


def mongo_update_job_status(
    system_job_id: str,
    instance_number: str,
    status: Status,
    node: dict,
) -> pymongo.results.UpdateResult:
    global mongo_jobs
    job = mongo_jobs.db.jobs.find_one({"system_job_id": str(system_job_id)})
    instance_list = job["instance_list"]
    for instance in instance_list:
        if int(instance.get("instance_number")) == int(instance_number):
            instance["status"] = status.value
            if node is not None:
                instance["host_ip"] = node["node_address"]
                port = node["node_info"].get("node_port")
                if port is None:
                    port = 50011
                instance["host_port"] = port
                instance["worker_id"] = node.get("_id")
            break
    return mongo_jobs.db.jobs.update_one(
        {"system_job_id": str(system_job_id)},
        {"$set": {"status": status.value, "instance_list": instance_list}},
    )


def mongo_get_services_with_failed_instanes():
    return mongo_jobs.db.jobs.find(
        {
            "$or": [
                {"instance_list.status": DeploymentStatus.FAILED.value},
                {"instance_list.status": DeploymentStatus.DEAD.value},
                {"instance_list.status": NegativeSchedulingStatus.NO_WORKER_CAPACITY.value},
            ]
        }
    )


def mongo_update_job_deployed(
    sname: str,
    instance_num: int,
    status: Status,
    publicip: str,
    workerid: str,
) -> Optional[pymongo.results.UpdateResult]:
    global mongo_jobs
    job = mongo_jobs.db.jobs.find_one({"job_name": sname})
    if job:
        instance_list = job.get("instance_list", [])
        updated = False
        for instance in range(len(instance_list)):
            if int(instance_list[instance]["instance_number"]) == int(instance_num):
                if instance_list[instance].get("worker_id") != workerid:
                    return None  # cannot update another worker's resources
                instance_list[instance]["status"] = status.value
                instance_list[instance]["publicip"] = publicip
                updated = True
        if updated:
            return mongo_jobs.db.jobs.update_one(
                {"job_name": sname}, {"$set": {"instance_list": instance_list}}
            )
    return None


def mongo_update_service_resources(
    sname: str,
    service: dict,
    workerid: str,
    instance_num: int = 0,
) -> Optional[pymongo.results.UpdateResult]:
    global mongo_jobs
    job = mongo_jobs.db.jobs.find_one({"job_name": sname})
    if job:
        instance_list = job["instance_list"]
        for instance in range(len(instance_list)):
            if int(instance_list[instance]["instance_number"]) == int(instance_num):
                if instance_list[instance].get("worker_id") != workerid:
                    return None  # cannot update another worker's resources
                instance_list[instance]["status"] = DeploymentStatus.RUNNING.value
                instance_list[instance]["status_detail"] = service.get("status_detail")
                instance_list[instance]["last_modified_timestamp"] = datetime.timestamp(
                    datetime.now()
                )
                instance_list[instance]["cpu"] = service.get("cpu")
                instance_list[instance]["memory"] = service.get("memory")
                instance_list[instance]["disk"] = service.get("disk")
                instance_list[instance]["logs"] = service.get("logs", "")
                return mongo_jobs.db.jobs.update_one(
                    {"job_name": sname}, {"$set": {"instance_list": instance_list}}
                )
    else:
        return None


def mongo_remove_job_instance(system_job_id, instance_number):
    global mongo_jobs
    job = mongo_jobs.db.jobs.find_one({"system_job_id": str(system_job_id)})
    instances = job["instance_list"]
    for instance in instances:
        if int(instance["instance_number"]) == int(instance_number) or int(instance_number) == -1:
            instances.remove(instance)
            break
    if len(instances) < 1:
        print("Removing job")
        print(job)
        return mongo_jobs.db.jobs.find_one_and_delete({"system_job_id": str(system_job_id)})
    else:
        return mongo_jobs.db.jobs.update_one(
            {"system_job_id": str(system_job_id)},
            {"$set": {"instance_list": instances}},
        )
