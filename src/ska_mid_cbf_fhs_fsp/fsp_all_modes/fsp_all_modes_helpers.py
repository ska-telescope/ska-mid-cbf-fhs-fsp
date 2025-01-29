from enum import Enum


class FrequencyBandEnum(Enum):
    _1 = 0
    _2 = 1
    _3 = 2
    _4 = 3
    _5A = 4
    _5B = 5


def freq_band_dict():
    band_map = {
        "1": FrequencyBandEnum(0),
        "2": FrequencyBandEnum(1),
        "3": FrequencyBandEnum(2),
        "4": FrequencyBandEnum(3),
        "5a": FrequencyBandEnum(4),
        "5b": FrequencyBandEnum(5),
    }
    return band_map
