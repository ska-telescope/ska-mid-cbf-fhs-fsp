from __future__ import annotations

import tango
from ska_control_model import HealthState, ObsState, ResultCode
from ska_mid_cbf_fhs_common import FhsBaseDevice
from ska_tango_base import SKAObsDevice
from ska_tango_base.base.base_device import DevVarLongStringArrayType
from tango import DevState
from tango.server import attribute, command, device_property

from ska_mid_cbf_fhs_fsp.fsp_all_modes.fsp_all_modes_component_manager import FSPAllModesComponentManager
from ska_mid_cbf_fhs_fsp.fsp_all_modes.fsp_all_modes_helpers import FSPMode


class FSPAllModesController(FhsBaseDevice):
    dev_a_fqdn = device_property(dtype="str")
    dev_b_fqdn = device_property(dtype="str")
    dev_c_fqdn = device_property(dtype="str")

    @attribute(
        abs_change=1,
        dtype=tango.DevEnum,
        enum_labels=[m.name for m in FSPMode],
        doc="FSP Mode",
    )
    def fspMode(self) -> FSPMode:
        return self.component_manager.fsp_mode

    @fspMode.write
    def fspMode(self, value: int | FSPMode) -> None:
        self.component_manager.fsp_mode = FSPMode(value)

    def init_device(self):
        # TODO: update FhsBaseDevice init_device to add some set_change_events() abstract/base method
        # so that we can avoid overriding init_device in every subclass with additional change events
        super(SKAObsDevice, self).init_device()
        self.set_change_event("communicationState", True)
        self.set_change_event("fspMode", True, True)
        self.set_state(DevState.ON)
        self.set_status("ON")
        self._update_health_state(HealthState.OK)
        self._update_obs_state(obs_state=ObsState.IDLE)

    def create_component_manager(self: FSPAllModesController) -> FSPAllModesComponentManager:
        return FSPAllModesComponentManager(
            device=self,
            logger=self.logger,
            attr_change_callback=self.push_change_event,
            attr_archive_callback=self.push_archive_event,
            health_state_callback=self._update_health_state,
            communication_state_callback=self._communication_state_changed,
            obs_command_running_callback=self._obs_command_running,
            component_state_callback=self._component_state_changed,
            obs_state_action_callback=self._obs_state_action,
        )

    def init_command_objects(self: FSPAllModesController) -> None:
        commandsAndMethods = [
            ("GoToIdle", "go_to_idle"),  # replacement for Deconfigure
            ("ConfigureBand", "configure_band"),
            ("ConfigureScan", "configure_scan"),
            ("Scan", "scan"),
            ("EndScan", "end_scan"),
            ("ObsReset", "obs_reset"),
            ("TestCmd", "test_cmd"),
        ]

        super().init_command_objects(commandsAndMethods)

    """
        Commands
    """

    @command(
        dtype_out="DevVarLongStringArray",
    )
    @tango.DebugIt()
    def TestCmd(self: FSPAllModesController) -> DevVarLongStringArrayType:
        return (
            [ResultCode.OK],
            ["TEST CMD OKAY."],
        )

    @command(
        dtype_in="DevString",
        dtype_out="DevVarLongStringArray",
        doc_in="Configuration json.",
    )
    def ConfigureScan(self: FSPAllModesController, config: str) -> DevVarLongStringArrayType:
        command_handler = self.get_command_object(command_name="ConfigureScan")
        result_code, command_id = command_handler(config)
        return [[result_code], [command_id]]

    @command(
        dtype_in="DevULong",
        dtype_out="DevVarLongStringArray",
        doc_in="Configuration json.",
    )
    def Scan(self: FSPAllModesController, scan_id: int) -> DevVarLongStringArrayType:
        command_handler = self.get_command_object(command_name="Scan")
        result_code, command_id = command_handler(scan_id)
        return [[result_code], [command_id]]

    @command(dtype_out="DevVarLongStringArray")
    def EndScan(self: FSPAllModesController) -> DevVarLongStringArrayType:
        command_handler = self.get_command_object(command_name="EndScan")
        result_code, command_id = command_handler()
        return [[result_code], [command_id]]

    @command(dtype_out="DevVarLongStringArray")
    def ObsReset(self: FSPAllModesController) -> DevVarLongStringArrayType:
        command_handler = self.get_command_object(command_name="ObsReset")
        result_code, command_id = command_handler()
        return [[result_code], [command_id]]


def main(args=None, **kwargs):
    return FSPAllModesController.run_server(args=args or None, **kwargs)


if __name__ == "__main__":
    main()
