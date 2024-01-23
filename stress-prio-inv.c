/*
 * Copyright (C) 2024      Colin Ian King.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#include "stress-ng.h"
#include "core-builtin.h"
#include "core-killpid.h"
#include "core-capabilities.h"
#include "core-pthread.h"

#if defined(HAVE_PTHREAD_NP_H)
#include <pthread_np.h>
#endif

/*
#define DEBUG_USAGE
*/

#define MUTEX_PROCS	(3)

#define STRESS_PRIO_INV_TYPE_INHERIT	(0)
#define STRESS_PRIO_INV_TYPE_NONE	(1)
#define STRESS_PRIO_INV_TYPE_PROTECT	(2)

/* must match order in stress_prio_inv_policies[] */
#define STRESS_PRIO_INV_POLICY_BATCH	(0)
#define STRESS_PRIO_INV_POLICY_IDLE	(1)
#define STRESS_PRIO_INV_POLICY_FIFO	(2)
#define STRESS_PRIO_INV_POLICY_OTHER	(3)
#define STRESS_PRIO_INV_POLICY_RR	(4)

static const stress_help_t help[] = {
	{ NULL,	"prio-inv",		"start N workers exercising priority inversion lock operations" },
	{ NULL,	"prio-inv-ops N",	"stop after N priority inversion lock bogo operations" },
	{ NULL, "prio-inv-policy P",	"select scheduler policy [ batch, idle, fifo, other, rr ]" },
	{ NULL,	"prio-inv-type T",	"lock protocol type, [ inherit | none | protect ]" },
	{ NULL,	NULL,			NULL }
};

typedef struct {
	const char *option;	/* prio-inv-type */
	const int  value;	/* STRESS_PRIO_INV_* value */
} stress_prio_inv_options_t;

typedef struct {
	int prio;		/* priority level */
	int niceness;		/* niceness */
	pid_t pid;		/* child pid */
	double usage;		/* user + system run time usage */
} stress_prio_inv_child_info_t;

static const stress_prio_inv_options_t stress_prio_inv_types[] = {
	{ "inherit",	STRESS_PRIO_INV_TYPE_INHERIT },
	{ "none",	STRESS_PRIO_INV_TYPE_NONE },
	{ "protect",	STRESS_PRIO_INV_TYPE_PROTECT },
};

static const stress_prio_inv_options_t stress_prio_inv_policies[] = {
	{ "batch",	STRESS_PRIO_INV_POLICY_BATCH },
	{ "idle",	STRESS_PRIO_INV_POLICY_IDLE },
	{ "fifo",	STRESS_PRIO_INV_POLICY_FIFO },
	{ "other",	STRESS_PRIO_INV_POLICY_OTHER },
	{ "rr",		STRESS_PRIO_INV_POLICY_RR },
};

static int stress_set_prio_inv_type(const char *opts)
{
	size_t i;

	for (i = 0; i < SIZEOF_ARRAY(stress_prio_inv_types); i++) {
		if (!strcmp(opts, stress_prio_inv_types[i].option)) {
			return stress_set_setting("prio-inv-type", TYPE_ID_INT, &stress_prio_inv_types[i].value);
		}
	}
	(void)fprintf(stderr, "prio-inv-type option '%s' not known, options are:", opts);
	for (i = 0; i < SIZEOF_ARRAY(stress_prio_inv_types); i++)
		(void)fprintf(stderr, "%s %s", i == 0 ? "" : ",", stress_prio_inv_types[i].option);
	(void)fprintf(stderr, "\n");

	return -1;
}

static int stress_set_prio_inv_policy(const char *opts)
{
	size_t i;

	for (i = 0; i < SIZEOF_ARRAY(stress_prio_inv_policies); i++) {
		if (!strcmp(opts, stress_prio_inv_policies[i].option)) {
			return stress_set_setting("prio-inv-policy", TYPE_ID_INT, &stress_prio_inv_policies[i].value);
		}
	}
	(void)fprintf(stderr, "prio-inv-policy option '%s' not known, options are:", opts);
	for (i = 0; i < SIZEOF_ARRAY(stress_prio_inv_policies); i++)
		(void)fprintf(stderr, "%s %s", i == 0 ? "" : ",", stress_prio_inv_policies[i].option);
	(void)fprintf(stderr, "\n");

	return -1;
}

static const stress_opt_set_func_t opt_set_funcs[] = {
	{ OPT_prio_inv_policy,	stress_set_prio_inv_policy},
	{ OPT_prio_inv_type,	stress_set_prio_inv_type},
	{ 0,			NULL },
};

#if defined(_POSIX_PRIORITY_SCHEDULING) &&		\
    defined(HAVE_LIB_PTHREAD) &&			\
    defined(HAVE_PTHREAD_MUTEXATTR_T) &&		\
    defined(HAVE_PTHREAD_MUTEXATTR_INIT) &&		\
    defined(HAVE_PTHREAD_MUTEXATTR_DESTROY) &&		\
    defined(HAVE_PTHREAD_MUTEXATTR_SETPRIOCEILING) &&	\
    defined(HAVE_PTHREAD_MUTEXATTR_SETPROTOCOL) &&	\
    defined(HAVE_PTHREAD_MUTEXATTR_SETROBUST) &&	\
    defined(HAVE_PTHREAD_MUTEX_T) &&			\
    defined(HAVE_PTHREAD_MUTEX_INIT) &&			\
    defined(HAVE_PTHREAD_MUTEX_DESTROY) &&		\
    defined(HAVE_SETPRIORITY) &&			\
    defined(HAVE_SCHED_SETSCHEDULER) &&			\
    defined(HAVE_SCHED_GET_PRIORITY_MIN) &&		\
    defined(HAVE_SCHED_GET_PRIORITY_MAX) &&		\
    (defined(SCHED_FIFO) ||				\
     defined(SCHED_RR) ||				\
     defined(SCHED_OTHER) ||				\
     defined(SCHED_BATCH) ||				\
     defined(SCHED_IDLE))

typedef struct {
	stress_prio_inv_child_info_t	child_info[MUTEX_PROCS];
	pthread_mutex_t mutex;
	stress_args_t *args;
} stress_prio_inv_info_t;

typedef void (*stress_prio_inv_func_t)(const size_t instance, stress_prio_inv_info_t *info);


static void stress_prio_inv_getrusage(stress_prio_inv_child_info_t *child_info)
{
	struct rusage usage;

	getrusage(RUSAGE_SELF, &usage);

	child_info->usage =
		(double)usage.ru_utime.tv_sec +
		((double)usage.ru_utime.tv_usec / 1000000.0) +
		(double)usage.ru_stime.tv_sec +
		((double)usage.ru_stime.tv_usec / 1000000.0);
}

static void cpu_exercise(const size_t instance, stress_prio_inv_info_t *prio_inv_info)
{
	stress_prio_inv_child_info_t *child_info = &prio_inv_info->child_info[instance];
	stress_args_t *args = prio_inv_info->args;

	do {
		stress_prio_inv_getrusage(child_info);
	} while (stress_continue(args));
}

/*
 *  mutex_exercise()
 *	exercise the mutex
 */
static void mutex_exercise(const size_t instance, stress_prio_inv_info_t *prio_inv_info)
{
	stress_prio_inv_child_info_t *child_info = &prio_inv_info->child_info[instance];
	stress_args_t *args = prio_inv_info->args;
	pthread_mutex_t *mutex = &prio_inv_info->mutex;

	do {
		if (UNLIKELY(pthread_mutex_lock(mutex) < 0)) {
			pr_fail("%s: pthread_mutex_lock failed, errno=%d (%s)\n",
				args->name, errno, strerror(errno));
			break;
		}

		stress_prio_inv_getrusage(child_info);
		stress_bogo_inc(args);

		if (UNLIKELY(pthread_mutex_unlock(mutex) < 0)) {
			pr_fail("%s: pthread_mutex_unlock failed, errno=%d (%s)\n",
				args->name, errno, strerror(errno));
			break;
		}
	} while (stress_continue(args));
}

static int stress_prio_inv_set_prio_policy(
	stress_args_t *args,
	const int prio,
	const int niceness,
	const int policy)
{
	struct sched_param param;
	int ret;

	switch (policy) {
#if defined(SCHED_FIFO)
	case SCHED_FIFO:
#endif
#if defined(SCHED_RR)
	case SCHED_RR:
#endif
#if defined(SCHED_FIFO) || defined(SCHED_RR)
		(void)shim_memset(&param, 0, sizeof(param));
		param.sched_priority = prio;
		ret = sched_setscheduler(0, policy, &param);
		if (ret < 0) {
			pr_fail("%s: cannot set scheduling priority to %d and policy, errno=%d (%s)\n",
				args->name, prio, errno, strerror(errno));
		}
		break;
#endif
	default:
		(void)shim_memset(&param, 0, sizeof(param));
		param.sched_priority = 0;
		ret = sched_setscheduler(0, policy, &param);
		if (ret < 0) {
			pr_fail("%s: cannot set scheduling priority to %d and policy, errno=%d (%s)\n",
				args->name, prio, errno, strerror(errno));
		}
		ret = setpriority(PRIO_PROCESS, 0, niceness);
		if (ret < 0) {
			pr_fail("%s: cannot set priority to %d, errno=%d (%s)\n",
				args->name, niceness, errno, strerror(errno));
		}
	}
	return ret;
}

static void stress_prio_inv_alarm_handler(int sig)
{
	(void)sig;

	_exit(0);
}

#if defined(SCHED_FIFO) ||	\
    defined(SCHED_RR)
static void stress_prio_inv_check_policy(
	stress_args_t *args,
	const int policy,
	int *sched_policy,
	const char *policy_name)
{
	if (!stress_check_capability(SHIM_CAP_IS_ROOT)) {
		if (*sched_policy == policy) {
			if (args->instance == 0) {
				pr_inf("%s: cannot set prio-inv-policy '%s' as non-root user, "
					"defaulting to 'other'\n",
					args->name, policy_name);
			}
#if defined(SCHED_OTHER)
			*sched_policy = SCHED_OTHER;
#else
			*sched_policy = -1;	/* Unknown! */
#endif
		}
	}
}
#endif

/*
 *  stress_prio_inv()
 *	stress system with priority changing mutex lock/unlocks
 */
static int stress_prio_inv(stress_args_t *args)
{
	size_t i;
	int prio_min, prio_max, prio_div, sched_policy = -1;
	int prio_inv_type = STRESS_PRIO_INV_TYPE_INHERIT;
	int prio_inv_policy = STRESS_PRIO_INV_POLICY_FIFO;
	int nice_min, nice_max, nice_div;
	int rc = EXIT_SUCCESS;
	const pid_t ppid = getpid();
	pthread_mutexattr_t mutexattr;
	stress_prio_inv_info_t *prio_inv_info;
	stress_prio_inv_child_info_t *child_info;
	const char *policy_name;
#if defined(DEBUG_USAGE)
	double total_usage;
#endif

	static const stress_prio_inv_func_t stress_prio_inv_funcs[MUTEX_PROCS] = {
		mutex_exercise,
		cpu_exercise,
		mutex_exercise,
	};

	prio_inv_info = (stress_prio_inv_info_t *)mmap(
				NULL, sizeof(*prio_inv_info),
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (prio_inv_info == MAP_FAILED) {
		pr_inf_skip("%s: cannot mmap prio_inv_info structure, errno=%d (%s), skipping stressor\n",
			args->name, errno, strerror(errno));
		return EXIT_NO_RESOURCE;
	}
	child_info = prio_inv_info->child_info;
	prio_inv_info->args = args;

	(void)stress_get_setting("prio-inv-type", &prio_inv_type);
	(void)stress_get_setting("prio-inv-policy", &prio_inv_policy);

	policy_name = stress_prio_inv_policies[prio_inv_policy].option;

	switch (prio_inv_policy) {
	default:
	case STRESS_PRIO_INV_POLICY_FIFO:
#if defined(SCHED_FIFO)
		sched_policy = SCHED_FIFO;
#endif
		break;
	case STRESS_PRIO_INV_POLICY_RR:
#if defined(SCHED_RR)
		sched_policy = SCHED_RR;
#endif
		break;
	case STRESS_PRIO_INV_POLICY_BATCH:
#if defined(SCHED_BATCH)
		sched_policy = SCHED_BATCH;
#endif
		break;
	case STRESS_PRIO_INV_POLICY_IDLE:
#if defined(SCHED_IDLE)
		sched_policy = SCHED_IDLE;
#endif
		break;
	case STRESS_PRIO_INV_POLICY_OTHER:
#if defined(SCHED_OTHER)
		sched_policy = SCHED_OTHER;
#endif
		break;
	}

	if (sched_policy == -1) {
#if defined(SCHED_OTHER)
		if (args->instance == 0) {
			pr_inf("%s: scheduling policy '%s' is not supported, "
				"defaulting to 'other'\n",
				args->name, policy_name);
			sched_policy = SCHED_OTHER;
		}
#else
		if (args->instance == 0) {
			pr_inf_skip("%s: cheduling policy '%s' is not supported, "
				"no default 'other' either, skipping stressor\n",
				args->name, policy_name);
		}
		rc = EXIT_NO_RESOURCE;
		goto unmap_prio_inv_info;
#endif
	}

#if defined(SCHED_FIFO)
	stress_prio_inv_check_policy(args, SCHED_FIFO, &sched_policy, policy_name);
#endif
#if defined(SCHED_RR)
	stress_prio_inv_check_policy(args, SCHED_RR, &sched_policy, policy_name);
#endif

	if (stress_sigchld_set_handler(args) < 0)
		return EXIT_NO_RESOURCE;

	/*
	 *  Attempt to use priority inheritance on mutex
	 */
	if (pthread_mutexattr_init(&mutexattr) < 0) {
		pr_fail("pthread_mutexattr_init failed: errno=%d (%s)\n",
			errno, strerror(errno));
		(void)pthread_mutex_destroy(&prio_inv_info->mutex);
		return EXIT_FAILURE;
	}

	/* niceness for non-RR and non-FIFO scheduling */
	nice_max = 0;	/* normal level */
	nice_min = 19;	/* very low niceness */
	nice_div = (nice_max - nice_min) / (MUTEX_PROCS - 1);

	/* prio for RR and FIFO scheduling */
	prio_min = sched_get_priority_min(sched_policy);
	prio_max = sched_get_priority_max(sched_policy);
	prio_div = (prio_max - prio_min) / (MUTEX_PROCS - 1);

	switch (prio_inv_type) {
#if defined(PTHREAD_PRIO_NONE)
	case STRESS_PRIO_INV_TYPE_NONE:
		VOID_RET(int, pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_NONE));
		break;
#endif
#if defined(PTHREAD_PRIO_INHERIT)
	case STRESS_PRIO_INV_TYPE_INHERIT:
		VOID_RET(int, pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT));
		break;
#endif
#if defined(PTHREAD_PRIO_PROTECT)
	case STRESS_PRIO_INV_TYPE_PROTECT:
		VOID_RET(int, pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_PROTECT));
		break;
#endif
	}
	VOID_RET(int, pthread_mutexattr_setprioceiling(&mutexattr, prio_max));
	VOID_RET(int, pthread_mutexattr_setrobust(&mutexattr, PTHREAD_MUTEX_ROBUST));
	if (pthread_mutex_init(&prio_inv_info->mutex, &mutexattr) < 0) {
		pr_fail("%s: pthread_mutex_init failed: errno=%d: (%s)\n",
			args->name, errno, strerror(errno));
		return EXIT_FAILURE;
	}

	stress_set_proc_state(args->name, STRESS_STATE_RUN);

	for (i = 0; i < MUTEX_PROCS; i++) {
		pid_t pid;

		child_info[i].prio = prio_min + (prio_div * i);
		child_info[i].niceness = nice_min + (nice_div * i);
		child_info[i].usage = 0.0;

		pid = fork();
		if (pid < 0) {
			pr_inf("%s: cannot fork child process, errno=%d (%s), skipping stressor\n",
				args->name, errno, strerror(errno));
			rc = EXIT_NO_RESOURCE;
			goto reap;
		} else if (pid == 0) {
			if (stress_sighandler(args->name, SIGALRM, stress_prio_inv_alarm_handler, NULL) < 0)
				pr_inf("%s: cannot set SIGALRM signal handler, process termination may not work\n", args->name);

			child_info[i].pid = getpid();

			if (stress_prio_inv_set_prio_policy(args, child_info[i].prio, child_info[i].niceness, sched_policy) < 0)
				_exit(EXIT_FAILURE);
			stress_prio_inv_funcs[i](i, prio_inv_info);

			(void)kill(ppid, SIGALRM);
			_exit(0);
		} else {
			child_info[i].pid = pid;
		}
	}

	if (stress_prio_inv_set_prio_policy(args, prio_max, nice_max, sched_policy) < 0) {
		rc = EXIT_FAILURE;
		goto reap;
	}

	/* Wait for termination */
	while (stress_continue(args))
		pause();

reap:
	stress_set_proc_state(args->name, STRESS_STATE_DEINIT);

	for (i = 0; i < MUTEX_PROCS; i++) {
		if (child_info[i].pid != -1) {
			if (stress_kill_and_wait(args, child_info[i].pid, SIGALRM, false) < 0)
				rc = EXIT_FAILURE;
		}
	}
	(void)pthread_mutexattr_destroy(&mutexattr);

#if defined(DEBUG_USAGE)
	total_usage = 0.0;
	for (i = 0; i < MUTEX_PROCS; i++) {
		total_usage += child_info[i].usage;
	}
	for (i = 0; i < MUTEX_PROCS; i++) {
		pr_inf("%zd %5.2f%% %d\n", i, child_info[i].usage / total_usage, child_info[i].prio);
	}
#endif

	switch (prio_inv_type) {
	default:
	case STRESS_PRIO_INV_TYPE_NONE:
	case STRESS_PRIO_INV_TYPE_PROTECT:
		break;
	case STRESS_PRIO_INV_TYPE_INHERIT:
		if ((child_info[2].usage < child_info[0].usage * 0.9) &&
		    (child_info[0].usage > 1.0)) {
			pr_fail("%s: mutex priority inheritance appears incorrect, low priority process has far more run time (%.2f secs) than high priority process (%.2f secs)\n",
			args->name, child_info[0].usage, child_info[2].usage);
		}
		break;
	}

	(void)pthread_mutex_destroy(&prio_inv_info->mutex);
#if !defined(SCHED_OTHER)
unmap_prio_inv_info:
#endif
	(void)munmap((void *)prio_inv_info, sizeof(*prio_inv_info));

	return rc;
}

stressor_info_t stress_prio_inv_info = {
	.stressor = stress_prio_inv,
	.class = CLASS_OS | CLASS_SCHEDULER,
	.opt_set_funcs = opt_set_funcs,
	.verify = VERIFY_ALWAYS,
	.help = help
};
#else
stressor_info_t stress_prio_inv_info = {
	.stressor = stress_unimplemented,
	.class = CLASS_OS | CLASS_SCHEDULER,
	.opt_set_funcs = opt_set_funcs,
	.verify = VERIFY_ALWAYS,
	.help = help,
	.unimplemented_reason = "built without librt, pthread_np.h, pthread or SCHED_* support"
};
#endif
