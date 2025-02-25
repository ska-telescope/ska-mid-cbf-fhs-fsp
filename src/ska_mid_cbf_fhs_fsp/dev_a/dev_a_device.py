# -*- coding: utf-8 -*-
#
# This file is part of the SKA Mid CBF FHS FSP project With inspiration gathered from the Mid.CBF MCS project
#
# Distributed under the terms of the BSD 3-clause new license.
# See LICENSE.txt for more info.


from __future__ import annotations

from ska_control_model import HealthState, ObsState
from ska_mid_cbf_fhs_common import FhsLowLevelDeviceBase
from ska_tango_base import SKAObsDevice
from tango import DevState
from tango.server import attribute, device_property

from ska_mid_cbf_fhs_fsp.dev_a.dev_a_component_manager import DevAComponentManager


class DevA(FhsLowLevelDeviceBase):
    DevAType = device_property(dtype="str")

    @attribute(dtype="str")
    def aAttr(self: DevA) -> str:
        return self.component_manager.a_attr

    @aAttr.write
    def aAttr(self: DevA, value: str) -> None:
        self.component_manager.a_attr = value
        self.push_change_event("aAttr", value)

    def init_device(self):
        super(SKAObsDevice, self).init_device()
        self.set_change_event("communicationState", True)
        self.set_change_event("aAttr", True, True)
        self.set_state(DevState.ON)
        self.set_status("ON")
        self._update_health_state(HealthState.OK)
        self._update_obs_state(obs_state=ObsState.IDLE)

    def create_component_manager(self: DevA) -> DevAComponentManager:
        return DevAComponentManager(
            device=self,
            attr_change_callback=self.push_change_event,
            attr_archive_callback=self.push_archive_event,
            health_state_callback=self._update_health_state,
            communication_state_callback=self._communication_state_changed,
            obs_command_running_callback=self._obs_command_running,
            component_state_callback=self._component_state_changed,
            obs_state_action_callback=self._obs_state_action,
            logger=self.logger,
        )

    def always_executed_hook(self: DevA) -> None:
        """Hook to be executed before any commands."""

    def delete_device(self: DevA) -> None:
        """Hook to delete device."""

    def init_command_objects(self: DevA) -> None:
        # init the LRC
        commandsAndMethods = [
            ("Start", "start"),
            ("Stop", "stop"),
            ("TestCmd", "test_cmd"),
        ]
        super().init_command_objects(commandsAndMethods)

        # init the fast commands
        commandsAndClasses = [
            ("Recover", FhsLowLevelDeviceBase.RecoverCommand),
            ("Configure", FhsLowLevelDeviceBase.ConfigureCommand),
            ("Deconfigure", FhsLowLevelDeviceBase.DeconfigureCommand),
            ("GetStatus", FhsLowLevelDeviceBase.GetStatusCommand),
            ("GoToIdle", FhsLowLevelDeviceBase.GoToIdleCommand),
        ]

        super().init_fast_command_objects(commandsAndClasses)


def main(args=None, **kwargs):
    return DevA.run_server(args=args or None, **kwargs)


if __name__ == "__main__":
    main()
