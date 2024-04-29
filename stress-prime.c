/*
 * Copyright (C) 2024      Colin Ian King
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

#if defined(HAVE_GMP_H)
#include <gmp.h>
#endif

#if defined(HAVE_MPFR_H)
#include <mpfr.h>
#endif

#define STRESS_PRIME_METHOD_FACTORIAL	(0)
#define STRESS_PRIME_METHOD_INC		(1)
#define STRESS_PRIME_METHOD_PWR2	(2)
#define STRESS_PRIME_METHOD_PWR10	(3)

#define STRESS_PRIME_PROGRESS_INC_SECS	(60.0)

static const stress_help_t help[] = {
	{ NULL,	"prime N",		"start N workers that find prime numbers" },
	{ NULL,	"prime-ops N",		"stop after N prime operations" },
	{ NULL, "prime-method M",	"method of searching for next prime [ factorial | inc | pwr2 | pwr10 ]" },
	{ NULL,	"prime-progress",	"show prime progress every 60 seconds (just first stressor instance)" },
	{ NULL,	"prime-start N",	"value N from where to start computing primes" },
	{ NULL,	NULL,		 	NULL }
};

typedef struct {
	const char *name;
	const int prime_method;
} stress_prime_method_t;

static const stress_prime_method_t stress_prime_methods[] = {
	{ "factorial",	STRESS_PRIME_METHOD_FACTORIAL },
	{ "inc",	STRESS_PRIME_METHOD_INC },
	{ "pwr2",	STRESS_PRIME_METHOD_PWR2 },
	{ "pwr10",	STRESS_PRIME_METHOD_PWR10 },
};

/*
 *  stress_set_prime_method()
 *	set the default prime method
 */
static int stress_set_prime_method(const char *name)
{
	size_t i;

	for (i = 0; i < SIZEOF_ARRAY(stress_prime_methods); i++) {
		if (!strcmp(stress_prime_methods[i].name, name)) {
			stress_set_setting("prime-method", TYPE_ID_SIZE_T, &stress_prime_methods[i].prime_method);
			return 0;
		}
	}

	(void)fprintf(stderr, "prime-method must be one of:");
	for (i = 0; i < SIZEOF_ARRAY(stress_prime_methods); i++) {
		(void)fprintf(stderr, " %s", stress_prime_methods[i].name);
	}
	(void)fprintf(stderr, "\n");

	return -1;
}

/*
 *  stress_set_prime_progress
 *	enable periodic prime progress information
 */
static int stress_set_prime_progress(const char *opt)
{
	return stress_set_setting_true("prime-progress", opt);
}

/*
 *  stress_set_prime_start
 *	define start value
 */
static int stress_set_prime_start(const char *opt)
{
	return stress_set_setting("prime-start", TYPE_ID_STR, opt);
}

static const stress_opt_set_func_t opt_set_funcs[] = {
	{ OPT_prime_method,	stress_set_prime_method },
	{ OPT_prime_progress,	stress_set_prime_progress },
	{ OPT_prime_start,	stress_set_prime_start },
	{ 0,			NULL },
};

#if defined(HAVE_GMP_H) &&	\
    defined(HAVE_LIB_GMP)

static sigjmp_buf jmpbuf;
static bool jumped;

static void MLOCKED_TEXT stress_prime_alarm_handler(int signum)
{
	static int count = 0;
	(void)signum;

	stress_continue_set_flag(false);
	count++;
	if (count > 1)
		siglongjmp(jmpbuf, 1);
}

/*
 *  stress_prime_start()
 *	parse prime start value
 */
static int stress_prime_start(char *prime_start, mpz_t start)
{
	/* Try to parse as a mpz integer */
	if (mpz_set_str(start, prime_start, 0) == 0) {
		mpz_t zero;
		int ret;

		mpz_init(zero);
		mpz_set_ui(zero, 0);

		/* Ensure it's positive */
		ret = mpz_cmp(zero, start);
		mpz_clear(zero);
		if (ret > 0)
			return -1;
	} else {
#if defined(HAVE_MPFR_H)
		/*
		 *  Try as float and convert to integer
		 */
		mpfr_t start_mpfr, zero;
		char *str = NULL;
		int ret;

		mpfr_init(start_mpfr);

		/* Try to parse as a mpfr floating point value, e.g 1e20 */
		if (mpfr_set_str(start_mpfr, prime_start, 0, MPFR_RNDZ) != 0) {
			mpfr_clear(start_mpfr);
			return -1;
		}

		mpfr_init(zero);
		mpfr_set_ui(zero, 0, MPFR_RNDZ);

		/* Ensure it's positive */
		ret = mpfr_cmp(zero, start_mpfr);
		mpfr_clear(zero);
		if (ret > 0)
			return -1;

		/* Convert to string */
		if (mpfr_asprintf(&str, "%0.Rf", start_mpfr) < 1)
			return -1;
		/* Convert string to mpz integer */
		ret = mpz_set_str(start, str, 0);
		mpfr_free_str(str);
		if (ret != 0)
			return -1;
#else
		return -1;
#endif
	}
	return 0;
}

static int OPTIMIZE3 stress_prime(stress_args_t *args)
{
	double rate, t_progress_secs;
	NOCLOBBER double duration = 0.0;
	NOCLOBBER size_t digits = 0;
	NOCLOBBER size_t t_start;
	uint64_t ops;
	mpz_t start, value, factorial;
	int prime_method = STRESS_PRIME_METHOD_INC;
	bool prime_progress = false;
	char *prime_start = NULL;

	mpz_inits(start, value, factorial, NULL);

	(void)stress_get_setting("prime-method", &prime_method);
	(void)stress_get_setting("prime-progress", &prime_progress);
	(void)stress_get_setting("prime-start", &prime_start);

	if (prime_start) {
		if (stress_prime_start(prime_start, start) < 0) {
			pr_err("%s: invalid --prime-start value '%s', aborting\n",
				args->name, prime_start);
			mpz_clears(start, value, factorial, NULL);
			return EXIT_FAILURE;
		}
	} else {
		mpz_set_ui(start, 1);
	}

	mpz_set_ui(factorial, 2);

	/* only report progress on instance 0 */
	if (args->instance > 0)
		prime_progress = false;

	stress_set_proc_state(args->name, STRESS_STATE_RUN);


	jumped = false;
	if (sigsetjmp(jmpbuf, 1) != 0) {
		jumped = true;
		goto finish;
	}

	t_start = stress_time_now();
	t_progress_secs = t_start + STRESS_PRIME_PROGRESS_INC_SECS;

	if (stress_sighandler(args->name, SIGALRM, stress_prime_alarm_handler, NULL) < 0)
		return EXIT_NO_RESOURCE;

	do {
		double t1, t2;

		t1 = stress_time_now();
		mpz_nextprime(value, start);
		t2 = stress_time_now();
		duration += t2 - t1;

		switch (prime_method) {
		default:
		case STRESS_PRIME_METHOD_FACTORIAL:
			mpz_mul(start, start, factorial);
			mpz_add_ui(factorial, factorial, 1);
			break;
		case STRESS_PRIME_METHOD_INC:
			mpz_add_ui(start, value, 2);
			break;
		case STRESS_PRIME_METHOD_PWR2:
			mpz_mul_ui(start, start, 2);
			break;
		case STRESS_PRIME_METHOD_PWR10:
			mpz_mul_ui(start, start, 10);
			break;
		}
		stress_bogo_inc(args);
		digits = mpz_sizeinbase(value, 10);

		if (prime_progress && (t2 >= t_progress_secs)) {
			duration = t2 - t_start;
			ops = stress_bogo_get(args);
			rate = (duration > 0.0) ? (3600.0 * (double)ops) / duration : 0.0;
			t_progress_secs += STRESS_PRIME_PROGRESS_INC_SECS;
			pr_inf("%s: %" PRIu64 " primes found, largest prime: %zu digits long, (~%.2f primes per hour)\n",
				args->name, stress_bogo_get(args), digits, rate);
		}
	} while (stress_continue(args));

finish:
	if (!jumped) {
		/*
		 *  Only garbage collect if we didn't siglongjmp
		 *  here to avoid any heap corruption
		 */
		mpz_clears(start, value, factorial, NULL);
	}

	ops = stress_bogo_get(args);
	pr_inf("%s: %" PRIu64 " primes found, largest prime: %zu digits long\n",
		args->name, ops, digits);

	rate = (duration > 0.0) ? (double)ops / duration : 0.0;
	stress_metrics_set(args, 0, "primes per second", rate, STRESS_HARMONIC_MEAN);

	stress_set_proc_state(args->name, STRESS_STATE_DEINIT);

	return EXIT_SUCCESS;
}

stressor_info_t stress_prime_info = {
	.stressor = stress_prime,
	.class = CLASS_CPU | CLASS_COMPUTE,
	.opt_set_funcs = opt_set_funcs,
	.verify = VERIFY_NONE,
	.help = help
};

#else

stressor_info_t stress_prime_info = {
	.stressor = stress_unimplemented,
	.class = CLASS_CPU | CLASS_COMPUTE,
	.opt_set_funcs = opt_set_funcs,
	.verify = VERIFY_NONE,
	.help = help,
	.unimplemented_reason = "built without gmp.h, or libgmp"
};

#endif
