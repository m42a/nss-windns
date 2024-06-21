#include <nss.h>

[[gnu::constructor]] void on_load()
{
	__nss_configure_lookup("hosts", "windns");
}
