from __future__ import annotations  # allow forward references in type hints

from dataclasses import dataclass
from typing import Any

import numpy as np
from dataclasses_json import dataclass_json
from ska_control_model import CommunicationStatus, ResultCode
from ska_mid_cbf_fhs_common import FhsLowLevelComponentManagerBase

from ska_mid_cbf_fhs_fsp.dev_a.dev_a_simulator import DevASimulator


@dataclass_json
@dataclass
class DevAConfig:
    something: str = "abcd"


##
# status class that will be populated by the APIs and returned to provide the status
##
@dataclass_json
@dataclass
class DevAStatus:
    a_value: str = "wxyz"


class DevAComponentManager(FhsLowLevelComponentManagerBase):
    def __init__(
        self: DevAComponentManager,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            *args,
            simulator_api=DevASimulator,
            **kwargs,
        )

        self.a_attr = "A_DEFAULT"

    def go_to_idle(self: DevAComponentManager) -> tuple[ResultCode, str]:
        result = self.deconfigure(DevAConfig().to_dict())

        if result[0] is not ResultCode.FAILED:
            result = super().go_to_idle()
        else:
            self.logger.error("Unable to go to idle, result from deconfiguring was FAILED")

        return result

    # --------------------
    # Public Commands
    # --------------------
    # TODO Determine what needs to be communicated with here
    def start_communicating(self: DevAComponentManager) -> None:
        """Establish communication with the component, then start monitoring."""
        if self._communication_state == CommunicationStatus.ESTABLISHED:
            self.logger.info("Already communicating.")
            return

        super().start_communicating()
