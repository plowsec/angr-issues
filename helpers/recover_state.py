import pickle

import shared


def save_analysis_state(project, simgr, filename_prefix="angr_analysis"):
    with open(f"{filename_prefix}_project.pkl", "wb") as project_file:
        pickle.dump(project, project_file, protocol=-1)

    with open(f"{filename_prefix}_simgr.pkl", "wb") as simgr_file:
        pickle.dump(simgr, simgr_file, protocol=-1)

    with open(f"{filename_prefix}_shared.pkl", "wb") as globals_file:
        pickle.dump({
            'FIRST_ADDR': shared.FIRST_ADDR,
            'DO_NOTHING': shared.DO_NOTHING,
            'mycc': shared.mycc,
            'cfg': shared.cfg,
            'driver_path': shared.driver_path,
            'phase': shared.phase
        }, globals_file, protocol=-1)

    with open(f"{filename_prefix}_state.pkl", "wb") as state_file:
        pickle.dump(shared.state, state_file, protocol=-1)


def restore_analysis_state(filename_prefix="angr_analysis"):
    with open(f"{filename_prefix}_project.pkl", "rb") as project_file:
        shared.proj = pickle.load(project_file)

    with open(f"{filename_prefix}_simgr.pkl", "rb") as simgr_file:
        shared.simgr = pickle.load(simgr_file)

    with open(f"{filename_prefix}_shared.pkl", "rb") as globals_file:
        globals_data = pickle.load(globals_file)
        shared.FIRST_ADDR = globals_data['FIRST_ADDR']
        shared.DO_NOTHING = globals_data['DO_NOTHING']
        shared.mycc = globals_data['mycc']
        shared.cfg = globals_data['cfg']
        shared.driver_path = globals_data['driver_path']
        shared.phase = globals_data['phase']

    with open(f"{filename_prefix}_state.pkl", "rb") as state_file:
        shared.state = pickle.load(state_file)



