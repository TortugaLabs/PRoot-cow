/*
 * This file is part of PRoot.
 *
 * Copyright (C) 2016 Alejandro Liu
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

#include <stdint.h>        /* intptr_t, */
#include <stdlib.h>        /* strtoul(3), */
#include <linux/version.h> /* KERNEL_VERSION, */
#include <assert.h>        /* assert(3), */
#include <sys/utsname.h>   /* uname(2), utsname, */
#include <string.h>        /* str*(3), memcpy(3), */
#include <talloc.h>        /* talloc_*, */
#include <fcntl.h>         /* AT_*,  */
#include <sys/ptrace.h>    /* linux.git:c0a3a20b  */
#include <errno.h>         /* errno,  */
#include <linux/auxvec.h>  /* AT_,  */
#include <linux/futex.h>   /* FUTEX_PRIVATE_FLAG */
#include <sys/param.h>     /* MIN, */
#include <sys/mman.h>	   /* mmap, munmap */
#include <unistd.h>	   /* unlink, close, write, fchown */

#include "extension/extension.h"
#include "syscall/seccomp.h"
#include "syscall/sysnum.h"
#include "syscall/syscall.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "execve/auxv.h"
#include "cli/note.h"
#include "arch.h"

typedef int Config;

/* List of syscalls handled by this extensions.  */
static FilteredSysnum filtered_sysnums[] = {
  { PR_open,		FILTER_SYSEXIT },
  { PR_openat,		FILTER_SYSEXIT },
  FILTERED_SYSNUM_END,
};

const char rand_path[] = "/dev/random";
const char urand_path[] = "/dev/urandom";

/**
 * Adjust current @tracee's syscall parameters according to @config.
 * This function always returns 0.
 */
static int handle_sysenter_end(Tracee *tracee, const Config *config UNUSED)
{
	word_t sysnum;
	char old_path[PATH_MAX];
	int status;

	sysnum = get_sysnum(tracee, ORIGINAL);
	switch (sysnum) {
	case PR_open:
	  /* Extract the currrent path. */
	  status = get_sysarg_path(tracee, old_path, SYSARG_1);
	  if (status < 0) return status;
	  if (!strcmp(old_path, rand_path)) {
		status = set_sysarg_path(tracee, urand_path, SYSARG_1);
		if (status < 0) return status;
	  }
	  //note(tracee, INFO, USER, "PR_open(%s)",old_path);
	  return 0;
	case PR_openat:
	  /* Extract the currrent path. */
	  status = get_sysarg_path(tracee, old_path, SYSARG_2);
	  if (status < 0) return status;
	  if (!strcmp(old_path, rand_path)) {
		status = set_sysarg_path(tracee, urand_path, SYSARG_2);
		if (status < 0) return status;
	  }
	  //note(tracee, INFO, USER, "PR_openat(%s)",old_path);
	  return 0;
	default:
		return 0;
	}

	/* Never reached  */
	assert(0);
	return 0;

}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occurred.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int badrand_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
		Config *config;
		extension->config = talloc(extension, Config);
		if (extension->config == NULL)
			return -1;

		config = talloc_get_type_abort(extension->config, Config);
		*config = 0;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case INHERIT_PARENT: /* Inheritable for sub reconfiguration ...  */
		return 1;

	case INHERIT_CHILD: {
		/* Copy the parent configuration to the child.  The
		 * structure should not be shared as uid/gid changes
		 * in one process should not affect other processes.
		 * This assertion is not true for POSIX threads
		 * sharing the same group, however Linux threads never
		 * share uid/gid information.  As a consequence, the
		 * GlibC emulates the POSIX behavior on Linux by
		 * sending a signal to all group threads to cause them
		 * to invoke the system call too.  Finally, PRoot
		 * doesn't have to worry about clone flags.
		 */

		Extension *parent = (Extension *) data1;
		extension->config = talloc_zero(extension, Config);
		if (extension->config == NULL)
			return -1;

		memcpy(extension->config, parent->config, sizeof(Config));
		return 0;
	}

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);

		return handle_sysenter_end(tracee, config);
	}


	default:
		return 0;
	}
}
