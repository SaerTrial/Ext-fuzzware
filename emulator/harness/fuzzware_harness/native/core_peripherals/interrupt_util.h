
#ifndef INTR_UTIL_H
#define INTR_UTIL_H

bool is_disabled_by_config(int exception_no) {
    for(int i = 0; i < num_config_disabled_interrupts; ++i) {
        if(config_disabled_interrupts[i] == exception_no) {
            return true;
        }
    }

    return false;
}


#endif