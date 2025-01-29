import subprocess

from tango.server import run

from ska_mid_cbf_fhs_fsp.dev_a.dev_a_device import DevA
from ska_mid_cbf_fhs_fsp.dev_b.dev_b_device import DevB
from ska_mid_cbf_fhs_fsp.dev_c.dev_c_device import DevC
from ska_mid_cbf_fhs_fsp.fsp_all_modes.fsp_all_modes_device import FSPAllModesController

__all__ = ["main"]


def main(args=None, **kwargs):  # noqa: E302
    # Call the kubectl command and wait until the bitstreams have been successfully downloaded
    wait_for_job_completion("bitstream-download-job")

    return run(
        classes=(
            DevA,
            DevB,
            DevC,
	    FSPAllModesController,
        ),
        args=args,
        **kwargs,
    )


def wait_for_job_completion(job_name) -> bool:
    cmd = ["kubectl", "wait", "--for=condition=complete", "--timeout=60s", f"job/{job_name}"]

    try:
        subprocess.run(cmd, check=True)
        print(f"Job {job_name} completed successfully...")
        return True
    except subprocess.CalledProcessError as ex:
        print(f"Job {job_name} did not complete successfully.. {repr(ex)}")
        return False


if __name__ == "__main__":  # noqa: #E305
    main()
