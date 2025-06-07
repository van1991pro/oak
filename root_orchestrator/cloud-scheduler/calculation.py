from typing import Union

from oakestra_utils.types.statuses import NegativeSchedulingStatus
from resource_abstractor_client import cluster_operations


def calculate(job: dict) -> Union[dict, NegativeSchedulingStatus]:
    print("calculating...")

    constraints = job.get("constraints")
    if constraints is not None and len(constraints) > 0:
        return constraint_based_scheduling(job, constraints)
    else:
        return greedy_load_balanced_algorithm(job=job)


def constraint_based_scheduling(job: dict, constraints) -> Union[dict, NegativeSchedulingStatus]:
    filtered_active_clusters = []
    active_clusters = list(cluster_operations.get_resources(active=True))
    for cluster in active_clusters:
        satisfying = True

        for constraint in constraints:
            constraint_type = constraint.get("type")
            # TODO(AM): Turn the constraints into an enum - put them into the oak-utils library.

            if constraint_type == "direct":
                return direct_service_mapping(job, constraint.get("cluster"))

            if constraint_type == "addons":
                for cluster in active_clusters:
                    if not (
                        cluster.get("supported_addons")
                        and constraint.get("needs")
                        and set(constraint.get("needs")).issubset(
                            set(cluster.get("supported_addons"))
                        )
                    ):
                        satisfying = False
                        continue

            if constraint_type == "clusters":
                for cluster in active_clusters:
                    cluster_name = cluster.get("cluster_name")
                    if not (cluster_name and cluster_name in constraint.get("allowed")):
                        satisfying = False

        if satisfying:
            filtered_active_clusters.append(cluster)

    return greedy_load_balanced_algorithm(job=job, active_clusters=filtered_active_clusters)


def direct_service_mapping(
    job: dict,
    cluster_name: str,
) -> Union[dict, NegativeSchedulingStatus]:
    cluster = cluster_operations.get_resource_by_name(cluster_name)

    if cluster is None:
        return NegativeSchedulingStatus.TARGET_CLUSTER_NOT_FOUND

    if not cluster["active"]:
        return NegativeSchedulingStatus.TARGET_CLUSTER_NOT_ACTIVE

    print("Cluster is active")
    if not does_cluster_respects_requirements(cluster, job):
        return NegativeSchedulingStatus.TARGET_CLUSTER_NO_CAPACITY

    return cluster


def first_fit_algorithm(job: dict) -> Union[dict, NegativeSchedulingStatus]:
    """Which of the clusters fits the Qos of the deployment file as the first"""
    active_clusters = cluster_operations.get_resources(active=True) or []

    print("active_clusters: ")
    for cluster in active_clusters:
        print(cluster)

        if does_cluster_respects_requirements(cluster, job):
            return cluster

    return NegativeSchedulingStatus.NO_ACTIVE_CLUSTER_WITH_CAPACITY


def greedy_load_balanced_algorithm(
    job: dict,
    active_clusters=None,
) -> Union[dict, NegativeSchedulingStatus]:
    """Which of the clusters have the most capacity for a given job"""

    if active_clusters is None:
        active_clusters = cluster_operations.get_resources(active=True) or []
    qualified_clusters = []

    for cluster in active_clusters:
        if does_cluster_respects_requirements(cluster, job):
            qualified_clusters.append(cluster)

    target_cluster = None
    target_cpu = 0
    target_mem = 0

    if not qualified_clusters:
        return NegativeSchedulingStatus.NO_ACTIVE_CLUSTER_WITH_CAPACITY

    # Return the cluster with the most cpu+ram.
    if job.get("virtualization") == "unikernel":
        arch = job.get("arch")
        for cluster in qualified_clusters:
            aggregation = cluster.get("aggregation_per_architecture", None)
            for a in arch:
                aggregation_arch = aggregation.get(a, None)
                if not aggregation_arch:
                    continue
                cpu = float(aggregation_arch.get("cpu_cores", 0))
                mem = float(aggregation_arch.get("memory_in_mb", 0))
                if cpu >= target_cpu and mem >= target_mem:
                    target_cpu = cpu
                    target_mem = mem
                    target_cluster = cluster
        return target_cluster

    for cluster in qualified_clusters:
        cpu = float(cluster.get("total_cpu_cores"))
        mem = float(cluster.get("memory_in_mb"))

        if cpu >= target_cpu and mem >= target_mem:
            target_cpu = cpu
            target_mem = mem
            target_cluster = cluster

    return target_cluster


def same_cluster_replication(job_obj, cluster_obj, replicas):
    job_description = job_obj.get("file_content")
    job_description.get("requirements").get("cpu")  # job_required_cpu_cores
    job_description.get("requirements").get("memory")  # job_required_memory
    cluster_obj.get("total_cpu_cores")  # cluster_cores_available
    cluster_obj.get("memory_in_mb")  # cluster_memory_available


def extract_specs(cluster):
    return {
        "available_cpu": cluster.get("total_cpu_cores")
        * (100 - cluster.get("aggregated_cpu_percent"))
        / 100,
        "available_memory": cluster.get("memory_in_mb"),
        "available_gpu": cluster.get("total_gpu_cores")
        * (100 - cluster.get("total_gpu_percent"))
        / 100,
        "virtualization": cluster.get("virtualization"),
    }


def extract_architecture_specs(cluster, arch):
    aggregation = cluster.get("aggregation_per_architecture", None)
    if aggregation is not None:
        aggregation = aggregation.get(arch, None)

        if aggregation is not None:
            return {
                "available_cpu": aggregation.get("cpu_cores")
                * (100 - aggregation.get("cpu_percent"))
                / 100,
                "available_memory": aggregation.get("memory_in_mb"),
                "virtualization": ["unikernel"],
                "available_gpu": 0,
            }

    return {
        "available_cpu": 0,
        "available_memory": 0,
        "virtualization": [],
        "available_gpu": 0,
    }


def does_cluster_respects_requirements(cluster, job):
    memory = 0
    if job.get("memory"):
        memory = job.get("memory")

    vcpu = 0
    if job.get("vcpu"):
        vcpu = job.get("vcpu")

    vgpu = 0
    if job.get("vgpu"):
        vgpu = job.get("vgpu")

    virtualization = job.get("virtualization")

    cluster_specs = None

    if virtualization == "unikernel":
        arch = job.get("arch")
        if arch is None:
            return False
        for a in arch:
            cluster_specs = extract_architecture_specs(cluster, a)
            if (
                cluster_specs["available_cpu"] >= vcpu
                and cluster_specs["available_memory"] >= memory
                and virtualization in cluster_specs["virtualization"]
                and cluster_specs["available_gpu"] >= vgpu
            ):
                return True
    else:
        cluster_specs = extract_specs(cluster)
        if (
            cluster_specs["available_cpu"] >= vcpu
            and cluster_specs["available_memory"] >= memory
            and virtualization in cluster_specs["virtualization"]
            and cluster_specs["available_gpu"] >= vgpu
        ):
            return True

    return False
