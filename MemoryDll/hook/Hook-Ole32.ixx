export module Hook:Ole32;

namespace hook
{
	void hook_ole32()
	{
		// Keep WMI available. Device-specific WMI result virtualization must be
		// implemented at the result interface rather than failing COM activation.
	}
}
