"""Shared, Binary-Ninja-free policy for corpus evaluator exit status."""

import os
import tempfile


_profiles = []


def configure_binary_ninja(prefix="delphinja-eval-"):
    """Create a unique isolated profile before an evaluator imports BN.

    Keep the TemporaryDirectory alive for the process lifetime; Binary Ninja
    may consult its profile after initial import while analysis is running.
    """
    from tools import bnenv
    profile = tempfile.TemporaryDirectory(prefix=prefix)
    bnenv.seed_user_directory(profile.name)
    os.environ["BN_USER_DIRECTORY"] = profile.name
    _profiles.append(profile)
    return profile.name


def percentage(value):
    """An argparse type for percentages in the inclusive range 0..100."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        raise ValueError("must be a number between 0 and 100")
    if not 0.0 <= out <= 100.0:
        raise ValueError("must be between 0 and 100")
    return out


def validation_problems(processed, errors=0, passed=None, checked=None,
                        minimum=100.0, allow_empty=False):
    """Explain why an evaluator run is not a passing correctness check.

    ``passed`` and ``checked`` are omitted for recall-only runs which have no
    independent correctness oracle.  Empty corpora and empty oracle overlap
    fail by default: otherwise a broken path or selection filter looks green.
    """
    problems = []
    if errors:
        problems.append("%d input%s failed to process" %
                        (errors, "" if errors == 1 else "s"))
    if not processed and not allow_empty:
        problems.append("no inputs were processed")
    if checked is not None:
        if checked == 0:
            if not allow_empty:
                problems.append("no independently checkable results overlapped")
        else:
            rate = 100.0 * (passed or 0) / checked
            if rate < minimum:
                problems.append("correctness %.2f%% is below %.2f%%" %
                                (rate, minimum))
    return problems


def exit_status(problems, report_only=False):
    """Return a shell status; report-only is the explicit fail-open mode."""
    return 0 if report_only or not problems else 1
