# helper_wrapper.py
from netsim.launch.runner import runner_entrypoint

def pattern_process_runner(pattern_id, pattern_class, kwargs, shared_queue, stats_dict, pid_map):
    runner_entrypoint(
        pattern_id=pattern_id,
        pattern_class=pattern_class,
        kwargs=kwargs,
        shared_queue=shared_queue,
        stats_dict=stats_dict,
        pid_map=pid_map
    )