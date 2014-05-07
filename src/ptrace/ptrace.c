/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2013 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <sys/ptrace.h> /* PTRACE_*,  */
#include <errno.h>      /* E*, */
#include <assert.h>     /* assert(3), */
#include <stdbool.h>    /* bool, true, false, */
#include <signal.h>     /* siginfo_t, */
#include <sys/uio.h>    /* struct iovec, */
#include <sys/param.h>  /* MIN(), MAX(), */
#include <string.h>     /* memcpy(3), */

#include "ptrace/ptrace.h"
#include "ptrace/user.h"
#include "tracee/tracee.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/event.h"
#include "cli/notice.h"

#include "compat.h"

static const char *stringify_ptrace(enum __ptrace_request request)
{
#define CASE_STR(a) case a: return #a; break;
	switch (request) {
	CASE_STR(PTRACE_TRACEME)	CASE_STR(PTRACE_PEEKTEXT)	CASE_STR(PTRACE_PEEKDATA)
	CASE_STR(PTRACE_PEEKUSER)	CASE_STR(PTRACE_POKETEXT)	CASE_STR(PTRACE_POKEDATA)
	CASE_STR(PTRACE_POKEUSER)	CASE_STR(PTRACE_CONT)		CASE_STR(PTRACE_KILL)
	CASE_STR(PTRACE_SINGLESTEP)	CASE_STR(PTRACE_GETREGS)	CASE_STR(PTRACE_SETREGS)
	CASE_STR(PTRACE_GETFPREGS)	CASE_STR(PTRACE_SETFPREGS)	CASE_STR(PTRACE_ATTACH)
	CASE_STR(PTRACE_DETACH)		CASE_STR(PTRACE_GETFPXREGS)	CASE_STR(PTRACE_SETFPXREGS)
	CASE_STR(PTRACE_SYSCALL)	CASE_STR(PTRACE_SETOPTIONS)	CASE_STR(PTRACE_GETEVENTMSG)
	CASE_STR(PTRACE_GETSIGINFO)	CASE_STR(PTRACE_SETSIGINFO)	CASE_STR(PTRACE_GETREGSET)
	CASE_STR(PTRACE_SETREGSET)	CASE_STR(PTRACE_SEIZE)		CASE_STR(PTRACE_INTERRUPT)
	CASE_STR(PTRACE_LISTEN) default: return "PTRACE_???"; }
}

/**
 * Translate the ptrace syscall made by @tracee into a "void" syscall
 * in order to emulate the ptrace mechanism within PRoot.  This
 * function returns -errno if an error occured (unsupported request),
 * otherwise 0.
 */
int translate_ptrace_enter(Tracee *tracee)
{
	word_t request;

	/* The ptrace syscall have to be emulated since it can't be nested.  */
	set_sysnum(tracee, PR_void);

	request = peek_reg(tracee, CURRENT, SYSARG_1);
	switch (request) {
	case PTRACE_ATTACH:
		notice(tracee, WARNING, INTERNAL, "ptrace request '%s' not supported yet",
			stringify_ptrace(request));
		return -ENOTSUP;

	default:
		/* Other requests are handled at the exit stage.  */
		break;
	}

	return 0;
}

/**
 * Emulate the ptrace syscall made by @tracee.  This function returns
 * -errno if an error occured (unsupported request), otherwise 0.
 */
int translate_ptrace_exit(Tracee *tracee)
{
	word_t request, pid, address, data, result;
	Tracee *ptracee, *ptracer;
	int forced_signal = -1;
	int signal;
	int status;

	/* Read ptrace parameters.  */
	request = peek_reg(tracee, ORIGINAL, SYSARG_1);
	pid     = peek_reg(tracee, ORIGINAL, SYSARG_2);
	address = peek_reg(tracee, ORIGINAL, SYSARG_3);
	data    = peek_reg(tracee, ORIGINAL, SYSARG_4);

	/* The TRACEME request is the only one used by a tracee.  */
	if (request == PTRACE_TRACEME) {
		ptracer = tracee->parent;
		ptracee = tracee;

		/* The emulated ptrace in PRoot has the same
		 * limitation as the real ptrace in the Linux kernel:
		 * only one tracer per process.  */
		if (PTRACEE.ptracer != NULL || ptracee == ptracer)
			return -EPERM;

		PTRACEE.ptracer = ptracer;
		PTRACER.nb_ptracees++;

		/* Detect when the ptracer has gone to wait before the
		 * ptracee has did the ptrace(ATTACHME) request.  */
		if (PTRACER.waits_in == WAITS_IN_KERNEL) {
			status = kill(ptracer->pid, SIGSTOP);
			if (status < 0)
				notice(tracee, WARNING, INTERNAL,
					"can't wake ptracer %d", ptracer->pid);
			else {
				ptracer->sigstop = SIGSTOP_IGNORED;
				PTRACER.waits_in = WAITS_IN_PROOT;
			}
		}

		return 0;
	}

	/* Here, the tracee is a ptracer.  Also, the requested ptracee
	 * has to be in the "stopped for ptracer" state.  */
	ptracer = tracee;
	ptracee = get_stopped_ptracee(ptracer, pid, false, __WALL);
	if (ptracee == NULL) {
		/* Ensure we didn't get there only because inheritance
		 * mechanism has missed this one.  */
		ptracee = get_tracee(tracee, pid, false);
		assert(ptracee == NULL || ptracee->parent != NULL);

		return -ESRCH;
	}

	/* Sanity checks.  */
	if (   PTRACEE.is_zombie
	    || PTRACEE.ptracer != ptracer
	    || pid == (word_t) -1)
		return -ESRCH;

	switch (request) {
	case PTRACE_SYSCALL:
		PTRACEE.ignore_syscall = false;
		forced_signal = (int) data;
		status = 0;
		break;  /* Restart the ptracee.  */

	case PTRACE_CONT:
		PTRACEE.ignore_syscall = true;
		forced_signal = (int) data;
		status = 0;
		break;  /* Restart the ptracee.  */

	case PTRACE_SINGLESTEP:
		ptracee->restart_how = PTRACE_SINGLESTEP;
		forced_signal = (int) data;
		status = 0;
		break;  /* Restart the ptracee.  */

	case PTRACE_DETACH:
		assert(PTRACER.nb_ptracees > 0);
		PTRACER.nb_ptracees--;
		PTRACEE.ptracer = NULL;
		status = 0;
		break;  /* Restart the ptracee.  */

	case PTRACE_KILL:
		status = ptrace(request, pid, NULL, NULL);
		break;  /* Restart the ptracee.  */

	case PTRACE_SETOPTIONS:
		PTRACEE.options = data;
		return 0;  /* Don't restart the ptracee.  */

	case PTRACE_GETEVENTMSG: {
		status = ptrace(request, pid, NULL, &result);
		if (status < 0)
			return -errno;

		poke_word(ptracer, data, result);
		if (errno != 0)
			return -errno;

		return 0;  /* Don't restart the ptracee.  */
	}

	case PTRACE_PEEKUSER:
		if (is_32on64_mode(ptracer)) {
			address = convert_user_offset(address);
			if (address == (word_t) -1)
				return -EIO;
		}
		/* Fall through.  */
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		errno = 0;
		result = (word_t) ptrace(request, pid, address, NULL);
		if (errno != 0)
			return -errno;

		poke_word(ptracer, data, result);
		if (errno != 0)
			return -errno;

		return 0;  /* Don't restart the ptracee.  */

	case PTRACE_POKEUSER:
		if (is_32on64_mode(ptracer)) {
			address = convert_user_offset(address);
			if (address == (word_t) -1)
				return -EIO;
		}

		status = ptrace(request, pid, address, data);
		if (status < 0)
			return -errno;

		return 0;  /* Don't restart the ptracee.  */

	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		if (is_32on64_mode(ptracer)) {
			word_t tmp;

			errno = 0;
			tmp = (word_t) ptrace(PTRACE_PEEKDATA, ptracee->pid, address, NULL);
			if (errno != 0)
				return -errno;

			data |= (tmp & 0xFFFFFFFF00000000ULL);
		}

		status = ptrace(request, pid, address, data);
		if (status < 0)
			return -errno;

		return 0;  /* Don't restart the ptracee.  */

	case PTRACE_GETSIGINFO:
	case PTRACE_GETFPREGS:
	case PTRACE_GETREGS: {
		size_t size;
		union {
			siginfo_t siginfo;
			struct user_regs_struct regs;
			struct user_fpregs_struct fpregs;
			uint32_t regs32[USER32_NB_REGS];
		} buffer;

		size = (request == PTRACE_GETSIGINFO
			? sizeof(buffer.siginfo)
			: request == PTRACE_GETFPREGS
			? sizeof(buffer.fpregs)
			: sizeof(buffer.regs));

		status = ptrace(request, pid, NULL, &buffer);
		if (status < 0)
			return -errno;

		if (request == PTRACE_GETREGS && is_32on64_mode(ptracer)) {
			struct user_regs_struct regs64;

			memcpy(&regs64, &buffer.regs, sizeof(struct user_regs_struct));

			convert_user_regs_struct(false,	(uint64_t *) &regs64, buffer.regs32);
			size = sizeof(buffer.regs32);
		}

		status = write_data(ptracer, data, &buffer, size);
		if (status < 0)
			return status;

		return 0;  /* Don't restart the ptracee.  */
	}

	case PTRACE_SETSIGINFO:
	case PTRACE_SETFPREGS:
	case PTRACE_SETREGS: {
		size_t size;
		union {
			siginfo_t siginfo;
			struct user_regs_struct regs;
			struct user_fpregs_struct fpregs;
			uint32_t regs32[USER32_NB_REGS];
		} buffer;

		size = (request == PTRACE_GETSIGINFO
			? sizeof(buffer.siginfo)
			: request == PTRACE_SETFPREGS
			? sizeof(buffer.fpregs)
			: is_32on64_mode(ptracer)
			? sizeof(buffer.regs32)
			: sizeof(buffer.regs));

		status = read_data(ptracer, &buffer, data, size);
		if (status < 0)
			return status;

		if (request == PTRACE_SETREGS && is_32on64_mode(ptracer)) {
			uint32_t regs32[USER32_NB_REGS];

			memcpy(regs32, buffer.regs32, sizeof(regs32));

			convert_user_regs_struct(true, (uint64_t *) &buffer.regs, regs32);
			size = sizeof(buffer.regs);
		}

		status = ptrace(request, pid, NULL, &buffer);
		if (status < 0)
			return -errno;

		return 0;  /* Don't restart the ptracee.  */
	}

	case PTRACE_GETREGSET: {
		struct iovec local_iovec;
		word_t remote_iovec_base;
		word_t remote_iovec_len;

		remote_iovec_base = peek_word(ptracer, data);
		if (errno != 0)
			return -errno;

		remote_iovec_len = peek_word(ptracer, data + sizeof_word(ptracer));
		if (errno != 0)
			return -errno;

		/* Sanity check.  */
		assert(__builtin_types_compatible_p(typeof(local_iovec.iov_len), word_t));

		local_iovec.iov_len  = remote_iovec_len;
		local_iovec.iov_base = talloc_zero_size(ptracer->ctx, remote_iovec_len);
		if (local_iovec.iov_base == NULL)
			return -ENOMEM;

		status = ptrace(PTRACE_GETREGSET, pid, address, &local_iovec);
		if (status < 0)
			return status;

		remote_iovec_len = local_iovec.iov_len =
			MIN(remote_iovec_len, local_iovec.iov_len);

		/* Update remote vector content.  */
		status = writev_data(ptracer, remote_iovec_base, &local_iovec, 1);
		if (status < 0)
			return status;

		/* Update remote vector length.  */
		poke_word(ptracer, data + sizeof_word(ptracer), remote_iovec_len);
		if (errno != 0)
			return -errno;

		return 0;  /* Don't restart the ptracee.  */
	}

	case PTRACE_SETREGSET: {
		struct iovec local_iovec;
		word_t remote_iovec_base;
		word_t remote_iovec_len;

		remote_iovec_base = peek_word(ptracer, data);
		if (errno != 0)
			return -errno;

		remote_iovec_len = peek_word(ptracer, data + sizeof_word(ptracer));
		if (errno != 0)
			return -errno;

		/* Sanity check.  */
		assert(__builtin_types_compatible_p(typeof(local_iovec.iov_len), word_t));

		local_iovec.iov_len  = remote_iovec_len;
		local_iovec.iov_base = talloc_zero_size(ptracer->ctx, remote_iovec_len);
		if (local_iovec.iov_base == NULL)
			return -ENOMEM;

		/* Copy remote content into the local vector.  */
		status = read_data(ptracer, local_iovec.iov_base,
				remote_iovec_base, local_iovec.iov_len);
		if (status < 0)
			return status;

		status = ptrace(PTRACE_SETREGSET, pid, address, &local_iovec);
		if (status < 0)
			return status;

		return 0;  /* Don't restart the ptracee.  */
	}

	default:
		notice(ptracer, WARNING, INTERNAL, "ptrace request '%s' not supported yet",
			stringify_ptrace(request));
		return -ENOTSUP;
	}

	/* Now, the initial tracee's event can be handled.  */
	signal = PTRACEE.event4.proot.pending
		? handle_tracee_event(ptracee, PTRACEE.event4.proot.value)
		: PTRACEE.event4.proot.value;

	/* The restarting signal from the ptracer overrides the
	 * restarting signal from PRoot.  */
	if (forced_signal != -1)
		signal = forced_signal;

	(void) restart_tracee(ptracee, signal);

	return status;
}