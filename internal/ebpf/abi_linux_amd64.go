//go:build linux && amd64

package ebpf

const (
	syscallArg0Offset = 112
	syscallArg1Offset = 104
	syscallArg2Offset = 96
	syscallArg3Offset = 56

	execveSyscallNumber  = 59
	connectSyscallNumber = 42

	openSyscallNumber    = 2
	openatSyscallNumber  = 257
	openat2SyscallNumber = 437
	hasOpenSyscall       = true

	writeSyscallNumber    = 1
	pwriteSyscallNumber   = 18
	writevSyscallNumber   = 20
	pwritevSyscallNumber  = 296
	pwritev2SyscallNumber = 328

	chmodSyscallNumber     = 90
	fchmodSyscallNumber    = 91
	fchmodatSyscallNumber  = 268
	fchmodat2SyscallNumber = 452
	hasChmodSyscall        = true

	renameSyscallNumber    = 82
	renameatSyscallNumber  = 264
	renameat2SyscallNumber = 316
	unlinkSyscallNumber    = 87
	unlinkatSyscallNumber  = 263
	mkdirSyscallNumber     = 83
	mkdiratSyscallNumber   = 258
	symlinkSyscallNumber   = 88
	symlinkatSyscallNumber = 266
	linkSyscallNumber      = 86
	linkatSyscallNumber    = 265
	truncateSyscallNumber  = 76
	ftruncateSyscallNumber = 77
	hasLegacyPathSyscalls  = true

	setuidSyscallNumber    = 105
	setgidSyscallNumber    = 106
	setreuidSyscallNumber  = 113
	setregidSyscallNumber  = 114
	setgroupsSyscallNumber = 116
	setresuidSyscallNumber = 117
	setresgidSyscallNumber = 119
	capsetSyscallNumber    = 126
	prctlSyscallNumber     = 157

	pivotRootSyscallNumber       = 155
	chrootSyscallNumber          = 161
	mountSyscallNumber           = 165
	umount2SyscallNumber         = 166
	unshareSyscallNumber         = 272
	setnsSyscallNumber           = 308
	ptraceSyscallNumber          = 101
	processVMReadvSyscallNumber  = 310
	processVMWritevSyscallNumber = 311
	bindSyscallNumber            = 49
	listenSyscallNumber          = 50
	initModuleSyscallNumber      = 175
	deleteModuleSyscallNumber    = 176
	kexecLoadSyscallNumber       = 246
	finitModuleSyscallNumber     = 313
	bpfSyscallNumber             = 321
)
