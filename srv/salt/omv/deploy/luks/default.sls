# Clevis is only needed by containers that use network (Tang) or TPM2
# auto-unlock. The LuksMgmt RPC runs this state with OMV_LUKS_CLEVIS_PINS set
# to a comma-separated list of the pins it is about to bind, so the packages
# are only installed when that type of auto-unlock is actually used.
{% set pins = salt['environ.get']('OMV_LUKS_CLEVIS_PINS', '').split(',') | select | list %}

{% if pins %}
luks_clevis_install:
  pkg.installed:
    - pkgs:
      - clevis
      - clevis-luks
      - clevis-systemd
{%- if 'tpm2' in pins %}
      - clevis-tpm2
{%- endif %}

# clevis-luks-askpass answers the systemd password prompts raised by
# systemd-cryptsetup at boot for crypttab entries without a key file.
luks_clevis_askpass_enable:
  service.enabled:
    - name: clevis-luks-askpass.path
    - require:
      - pkg: luks_clevis_install

{%- if 'tang' in pins %}

# Tang bound containers use _netdev in crypttab, which places them under
# remote-cryptsetup.target so they are unlocked once the network is up.
luks_remote_cryptsetup_enable:
  service.enabled:
    - name: remote-cryptsetup.target
{%- endif %}
{% endif %}
