//go:build linux && arm64

package ebpf

const (
	syscallArg0Offset = 0
	syscallArg1Offset = 8
	syscallArg2Offset = 16
	syscallArg3Offset = 24

	execveSyscallNumber  = 221
	connectSyscallNumber = 203

	openSyscallNumber    = 0
	openatSyscallNumber  = 56
	openat2SyscallNumber = 437
	hasOpenSyscall       = false

	writeSyscallNumber    = 64
	pwriteSyscallNumber   = 68
	writevSyscallNumber   = 66
	pwritevSyscallNumber  = 70
	pwritev2SyscallNumber = 287

	chmodSyscallNumber     = 0
	fchmodSyscallNumber    = 52
	fchmodatSyscallNumber  = 53
	fchmodat2SyscallNumber = 452
	hasChmodSyscall        = false

	renameSyscallNumber    = 9001
	renameatSyscallNumber  = 38
	renameat2SyscallNumber = 276
	unlinkSyscallNumber    = 9002
	unlinkatSyscallNumber  = 35
	mkdirSyscallNumber     = 9003
	mkdiratSyscallNumber   = 34
	symlinkSyscallNumber   = 9004
	symlinkatSyscallNumber = 36
	linkSyscallNumber      = 9005
	linkatSyscallNumber    = 37
	truncateSyscallNumber  = 45
	ftruncateSyscallNumber = 46
	hasLegacyPathSyscalls  = false

	setuidSyscallNumber    = 146
	setgidSyscallNumber    = 144
	setreuidSyscallNumber  = 145
	setregidSyscallNumber  = 143
	setgroupsSyscallNumber = 159
	setresuidSyscallNumber = 147
	setresgidSyscallNumber = 149
	capsetSyscallNumber    = 91
	prctlSyscallNumber     = 167

	pivotRootSyscallNumber       = 41
	chrootSyscallNumber          = 51
	mountSyscallNumber           = 40
	umount2SyscallNumber         = 39
	unshareSyscallNumber         = 97
	setnsSyscallNumber           = 268
	ptraceSyscallNumber          = 117
	processVMReadvSyscallNumber  = 270
	processVMWritevSyscallNumber = 271
	bindSyscallNumber            = 200
	listenSyscallNumber          = 201
	initModuleSyscallNumber      = 105
	deleteModuleSyscallNumber    = 106
	kexecLoadSyscallNumber       = 104
	finitModuleSyscallNumber     = 273
	bpfSyscallNumber             = 280
)
