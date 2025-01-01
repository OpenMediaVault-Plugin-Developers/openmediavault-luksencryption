<?php
/**
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    Volker Theile <volker.theile@openmediavault.org>
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2015 Volker Theile
 * @copyright Copyright (c) 2015-2025 openmediavault plugin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

use OMV\System\Process;

class OMVRpcServiceLuksMgmt extends \OMV\Rpc\ServiceAbstract {

    private $mountOnUnlock = TRUE;

    /**
     * Get the RPC service name.
     */
    public function getName() {
        return "LuksMgmt";
    }

    /**
     * Initialize the RPC service.
     */
    public function initialize() {
        if(isset($GLOBALS['OMV_LUKS_MOUNT_ON_UNLOCK']))
            $this->mountOnUnlock = boolvalEx($GLOBALS['OMV_LUKS_MOUNT_ON_UNLOCK']);

        $this->registerMethod("enumerateContainers");
        $this->registerMethod("getContainersList");
        $this->registerMethod("getContainerCandidates");
        $this->registerMethod("getContainerDetails");
        $this->registerMethod("createContainer");
        $this->registerMethod("deleteContainer");
        $this->registerMethod("modifyContainer");
        $this->registerMethod("openContainer");
        $this->registerMethod("closeContainer");
        $this->registerMethod("addContainerKey");
        $this->registerMethod("changeContainerKey");
        $this->registerMethod("removeContainerKey");
        $this->registerMethod("testContainerKey");
        $this->registerMethod("killContainerKeySlot");
        $this->registerMethod("backupContainerHeader");
        $this->registerMethod("restoreContainerHeader");
    }

    /**
     * Enumerate all LUKS containers on the system.
     * @param params The method parameters.
     * @param context The context of the caller.
     * @return An array of objects. Each object represents a LUKS container
     *     with the following properties:
     *     device file, uuid, size, status
     * @throw E_EXEC_MISC
     */
    public function enumerateContainers($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Enumerate all LUKS containers on the system.
        $devs = \OMV\System\Storage\Luks\Containers::enumerate();
        $result = [];
        foreach($devs as $devk => $devv) {
            // Get the container details.
            $luks = new \OMV\System\Storage\Luks\Container($devv);
            if(!$luks->exists())
                continue;
            $result[] = [
                "devicefile"            => $luks->getDeviceFile(),
                "uuid"                  => $luks->getUuid(),
                "size"                  => $luks->getSize(),
                "unlocked"              => $luks->isOpen(),
                "decrypteddevicefile"   => $luks->getDecryptedDeviceFile(),
                "usedslots"             => $luks->getUsedKeySlots(),
                "luksversion"           => $luks->getLuksVersion(),
                "lukslabel"             => $luks->getLuksLabel()
            ];
        }
        return $result;
    }

    /**
     * Get a list of LUKS containers.
     * @param params An array containing the following fields:
     *     \em start The index where to start.
     *     \em limit The number of objects to process.
     *     \em sortfield The name of the column used to sort.
     *     \em sortdir The sort direction, ASC or DESC.
     * @param context The context of the caller.
     * @return An array containing the requested objects. The field \em total
     *     contains the total number of objects, \em data contains the object
     *     array. An exception will be thrown in case of an error.
     */
    public function getContainersList($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.common.getlist");
        // Enumerate all LUKS containers on the system.
        $containers = $this->callMethod("enumerateContainers", NULL, $context);
        foreach($containers as $luksk => &$luksv) {
            $used = (!$luksv['unlocked']) ? NULL : FALSE;
            // If open, does the container contain a filesystem and is it known
            // or used (i.e. a configured mntent, aka referenced in /etc/fstab)?
            if(!is_null($used)) {
                if (FALSE !== \OMV\Rpc\Rpc::call("FsTab", "getByFsName",
                    [ "fsname" => $luksv['decrypteddevicefile'] ], $context)) {
                        $used = TRUE;
                }
            }
            // null if locked, otherwise true if used, false if not
            $luksv['_used'] = $used;
        }
        // Filter result.
        return $this->applyFilter($containers,
            $params['start'],
            $params['limit'],
            $params['sortfield'],
            $params['sortdir']
        );
    }

    /**
     * Get list of devices that can be used to create a LUKS container.
     * @param params The method parameters.
     * @param context The context of the caller.
     * @return An array containing objects with the following fields:
     *     devicefile, size and description.
     * @throw E_EXEC_MISC
     */
    public function getContainerCandidates($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Get a list of all potential usable devices.
        if (FALSE === ($devs = \OMV\System\Storage\StorageDevice::enumerateUnused()))
            throw new \OMV\Exception("Failed to get list of unused devices.");
        // Prepare the result list.
        $result = [];
        foreach ($devs as $devk => $devv) {
            // Get the object that implements the given storage device.
            $sd = \OMV\System\Storage\StorageDevice::getStorageDevice($devv);
            if (is_null($sd) || !$sd->exists())
                continue;
            // Skip read-only devices like CDROM.
            if (TRUE === $sd->isReadOnly())
                continue;
            // Check if device is referenced/used by a plugin.
            // Not implemented
            // Does this device already contain a filesystem?
            if (FALSE !== \OMV\System\Filesystem\Filesystem::hasFileSystem(
              $sd->getDeviceFile()))
                continue;
            // Is the device an already open LUKS container?
            // Don't allow LUKS-on-LUKS
            $luks = new \OMV\System\Storage\StorageDeviceLuks($sd->getDeviceFile());
            if (TRUE === $luks->isLuks())
                continue;
            // The device is a potential candidate
            // to be used as a LUKS container.
            $result[] = [
                "devicefile"    => $sd->getDeviceFile(),
                "size"          => $sd->getSize(),
                "vendor"        => $sd->getVendor(),
                "serialnumber"  => $sd->getSerialNumber(),
                "description"   => $sd->getDescription()
            ];
        }
        return $result;
    }

    /**
     * Get detail about a LUKS device.
     * @param params An array containing the following fields:
     *     \em devicefile The LUKS device file to get details from.
     * @param context The context of the caller.
     * @return The details of the given LUKS device as string.
     * @throw E_MISC_FAILURE
     */
    public function getContainerDetails($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.devicefile");
        // Get LUKS header details.
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if(FALSE === $luks->exists()) {
            throw new \OMV\Exception(sprintf(gettext("LUKS container on '%s' not found"),
                $params['devicefile']));
        }
        $detail = $luks->getDetail();
        return ($detail);
    }

    /**
     * Open (unlock) a LUKS container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device.
     *     \em devicefile The block special device of the LUKS container to open.
     *      And containing either passphrase or key file fields:
     *     \em passphrase The passphrase to unlock the device.
     *     \em keyfile Path to the uploaded key file to unlock the device.
     * @param context The context of the caller.
     * @return None
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function openContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.opencontainer");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(sprintf(gettext("LUKS container on '%s' not found"),
                $params['devicefile']));
        }
        // Check that the container is not already open, then use
        // the supplied passphrase or key file to unlock it if not.
        if (FALSE === $luks->isOpen()) {
            if(isset($params['keyfile']) && !empty($params['keyfile'])) {
                $key = $params['keyfile'];
                $keyIsFile = TRUE;
            } else {
                $key = $params['passphrase'];
                $keyIsFile = FALSE;
            }
            try {
                $luks->open($key, $keyIsFile);
            } catch(Exception $e) {
                throw new \OMV\Exception(sprintf(gettext("Unable to unlock encrypted device: %s"),
                    $e->getMessage()));
            }
        }
        /* Downstream operations with the decrypted container */
        $sdluks = new \OMV\System\Storage\StorageDeviceLuks($luks->getDecryptedDeviceFile());
        $df = $sdluks->getDeviceFile();
        // If the container contains an LVM physical volume, determine the
        // volume group and activate it (otherwise the logical volume and any
        // filesystem on it won't be accessible)
        if (class_exists("\OMV\System\Storage\Lvm\PhysicalVolume")) {
            // Use LVM plugin if it's installed to get VG name
            $pv = new \OMV\System\Storage\Lvm\PhysicalVolume($df);
            if (TRUE === $pv->exists()) {
                $vgName = $pv->getVGName();
            }
        } else {
            // Fall back to manual method without LVM plugin
            $cmd = sprintf("export LANG=C; pvdisplay --noheadings -C -o vg_name %s",
                escapeshellarg($df)
            );
            if (0 === $this->exec($cmd, $output)) {
                $vgName = trim($output[0]);
            }
        }
        // PV/VG was found - activate the VG, set devicefile to LV via
        // LVM plugin if available - although LVM/udev seems to
        // automatically mount filesystems in fstab from logical
        // volumes when activated, so probably not strictly necessary.
        if (isset($vgName)) {
            $this->debug(sprintf("%s contains an LVM2 PV, part of VG: %s",
                                 $df, $vgName));
            $cmd = sprintf("export LANG=C; vgchange -a y %s",
                escapeshellarg($vgName)
            );
            if (0 !== $this->exec($cmd, $output)) {
                $this->debug($output);
            } else {
                if (class_exists("\OMV\System\Storage\Lvm\VolumeGroup")) {
                    $vg = new \OMV\System\Storage\Lvm\VolumeGroup($vgName);
                    $lvNames = $vg->getLVName();
                    $fsDevs = array_map(function($lv) use ($vgName) {
                                            return "/dev/$vgName-$lv";
                                        }, $lvNames);
                }
            }
        } else {
            // If not an LVM2 PV, just pass the container devicefile
            $fsDevs = [ $df ];
        }
        // If the container contains a (referenced) filesystem, then mount it
        // (unless this automounting is disabled by the global configuration
        // option, OMV_LUKS_MOUNT_ON_UNLOCK - see initialize() above)
        if(TRUE === $this->mountOnUnlock) {
            foreach ($fsDevs as $dev) {
                $this->mountContainerFS($dev, $context);
            }
        }
    }

    /**
     * Helper function for mounting filesystems inside containers on unlocking.
     * @param devicefile The decrypted block special device of the
     *                   filesystem (inside the LUKS container) to mount.
     * @param context The context of the caller.
     * @return None.
     */
    private function mountContainerFS($deviceFile, $context) {
        if (FALSE !== \OMV\Rpc\Rpc::call("FileSystemMgmt", "hasFilesystem", 
                [ "devicefile" => $deviceFile ], $context)) {
            $meObject = \OMV\Rpc\Rpc::call("FsTab", "getByFsName", 
                [ "fsname" => $deviceFile ], $context);
            if (FALSE !== $meObject) {
                switch (strtolower($meObject['type'])) {
                case "btrfs":
                    /**
                     * Check if the unlocked device is part of a multi-
                     * device BTRFS filesystem, and don't attempt to mount
                     * it if it's not ready (not all devices are available,
                     * e.g. if more containers must be unlocked first, wait
                     * until they are all open).
                     * Note: using 'btrfs device ready' only works for the
                     * first time devices are opened - even if LUKS devices
                     * that are part of a multi-device BTRFS filesystem are
                     * later closed, some information is cached and so btrfs
                     * subsequently always reports the filesystem as ready.
                     * Hence, this workaround checks the number of devices
                     * online for the filesystem via 'btrfs filesystem show'
                     * instead, which should be more reliable.
                     * TODO: submit a patch to the core BTRFS backend that
                     * exposes this in a class function instead?
                     */
                    // Find out how many devices are in the filesystem
                    $cmd = sprintf("export LANG=C; btrfs filesystem ".
                                    "show %s | grep 'Total devices' | ".
                                    "awk '{print $3}'",
                                    escapeshellarg($meObject['fsname']));
                    $process = new Process($cmd);
                    $process->execute($output,$result);
                    $totalDevices = (int)$output[0];
                    // If the fs has fewer than one device (an error
                    // of some kind occurred), skip mounting
                    if($totalDevices < 1)
                        continue;
                    unset($cmd, $output, $result);
                    // Find out how many are online
                    $cmd = sprintf("export LANG=C; btrfs filesystem ".
                                    "show %s | grep 'devid' | wc -l",
                                    escapeshellarg($meObject['fsname']));
                    $process = new Process($cmd);
                    $process->execute($output,$result);
                    $availableDevices = (int)$output[0];
                    // If not all devices are online, skip mounting
                    if($availableDevices !== $totalDevices)
                        continue;
                    unset($cmd, $output, $result);
                case "ext2":
                case "ext3":
                case "ext4":
                case "jfs":
                case "xfs":
                case "hfsplus":
                case "reiserfs":
                case "iso9660":
                case "udf":
                case "vfat":
                case "ntfs":
                default:
                    $fsbMngr = \OMV\System\Filesystem\Backend\Manager::getInstance();
                    $fsb = $fsbMngr->getBackendById($meObject['fsname']);
                    $fs = $fsb->getImpl($meObject['fsname']);
                    if (FALSE === $fs->isMounted()) {
                        $fs->mount();
                    }
                }
            }
        }
    }

    /**
     * Close (lock) a LUKS container.
     * @param params An array containing the following fields:
     *     \em devicefile The block special device of the LUKS container to close.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function closeContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.devicefile");

        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(sprintf(gettext("LUKS container on '%s' not found"),
                $params['devicefile']));
        }
        // Check if the container is open, and proceed to close it if so
        if (TRUE === $luks->isOpen()) {
            try {
                $luks->close();
            } catch(Exception $e) {
                throw new \OMV\Exception(sprintf(gettext("Unable to lock encrypted device: %s"),
                    $e->getMessage()));
            }
        }
    }

    /**
     * Create a LUKS container.
     * @param params An array containing the following fields:
     *     \em devicefile The device file where to create the LUKS container.
     *     And containing either passphrase or key file fields:
     *     \em passphrase The passphrase to unlock the device.
     *     \em keyfile Path to the uploaded key file to unlock the device.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_DEVICE_NOT_FOUND
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     * @throw E_EXEC_MISC
     */
    public function createContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.createcontainer");
        // Get the storage device object.
        $sd = \OMV\System\Storage\StorageDevice::getStorageDevice($params['devicefile']);
        if (is_null($sd) || !$sd->exists()) {
            throw new \OMV\Exception(sprintf(gettext("Device '%s' not found"),
                $params['devicefile']));
        }
        // Get the storage device backend of the given device.
        $mngr = \OMV\System\Storage\Backend\Manager::getInstance();
        $sdb = $mngr->getBackend($sd->getDeviceFile());
        if (is_null($sdb)) {
            throw new \OMV\Exception(sprintf(
                gettext("No storage device backend exists for device %s"),
                $sd->getDeviceFile()));
        }
        switch ($sdb->getType()) {
        case OMV_STORAGE_DEVICE_TYPE_SOFTWARERAID:
        case OMV_STORAGE_DEVICE_TYPE_DEVICEMAPPER:
            // Wipe existing filesystems.
            $cmd = sprintf("export LANG=C; wipefs -a %s 2>&1",
                            $sd->getDeviceFile());
            if (0 !== $this->exec($cmd, $output)) {
                throw new \OMV\Exception($cmd . implode("\n", $output));
            }
            break;
        default:
            // Wipe existing filesystems.
            $cmd = sprintf("export LANG=C; sgdisk --zap-all %s 2>&1",
                            escapeshellarg($sd->getDeviceFile()));
            if (0 !== $this->exec($cmd, $output)) {
                throw new \OMV\Exception($cmd . implode("\n", $output));
            }
            break;
        }
        // Reread partition table.
        $cmd = sprintf("export LANG=C; partprobe %s",
                        escapeshellarg($sd->getDeviceFile()));
        if (0 !== $this->exec($cmd, $output)) {
            throw new \OMV\Exception($cmd . implode("\n", $output));
        }
        // Create the container.
        $cipher = $params['cipher'];
        $label = $params['lukslabel'];
        $luks = new \OMV\System\Storage\Luks\Container($sd->getDeviceFile());
        if(isset($params['keyfile']) && !empty($params['keyfile'])) {
            $key = $params['keyfile'];
            $keyIsFile = TRUE;
        } else {
            $key = $params['passphrase'];
            $keyIsFile = FALSE;
        }
        try {
            $luks->create($key, $keyIsFile, $cipher, $label);
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(gettext("Unable to create encrypted device: %s"),
                $e->getMessage()));
        }
        // Notify configuration changes.
        $dispatcher = \OMV\Engine\Notify\Dispatcher::getInstance();
        $dispatcher->notify(OMV_NOTIFY_CREATE,
              "org.openmediavault.system.storage.luks.container",
              [ "devicefile" => $params['devicefile'] ]
        );
    }

    /**
     * Delete a LUKS container.
     * @param params An array containing the following fields:
     *     \em devicefile The devicefile of the LUKS device.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     */
    public function deleteContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.devicefile");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Remove the container.
        try {
            $luks->remove();
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(gettext("Unable to remove encrypted device: %s"),
                $e->getMessage()));
        }
        // Notify configuration changes.
        $dispatcher = \OMV\Engine\Notify\Dispatcher::getInstance();
        $dispatcher->notify(OMV_NOTIFY_DELETE,
              "org.openmediavault.system.storage.luks.container",
              [ "devicefile" => $params['devicefile'] ]
        );
    }

    /**
     * Modify a LUKS container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device.
     *     \em devicefile The device file of the container to modify.
     *     \em openatboot A boolean value representing whether to unlock
     *         the encrypted device at boot or not.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     */
    public function modifyContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.modifycontainer");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Set the unlock at boot status
        // TODO: change crypttab method
        // Notify configuration changes.
        // Notify configuration changes.
        $dispatcher = \OMV\Engine\Notify\Dispatcher::getInstance();
        $dispatcher->notify(OMV_NOTIFY_MODIFY,
            "org.openmediavault.system.storage.luks.container",
            [
                "devicefile" => $params['devicefile'],
                "openatboot" => array_boolval($params, "openatboot")
            ]
        );
    }

    /**
     * Add a key to a container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device.
     *     \em devicefile The block special device of the LUKS container to modify.
     *      And containing either passphrase or file fields for old & new:
     *     \em oldpassphrase A current passphrase that will unlock the device.
     *     \em newpassphrase The new passphrase to add.
     *     \em oldkeyfile Path to the uploaded key file that unlocks the device.
     *     \em newkeyfile Path to the uploaded key file to add.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function addContainerKey($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.containerkey");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Build the command depending on the mix of passphrases and key files
        if(isset($params['oldkeyfile']) && !empty($params['oldkeyfile'])) {
            $old = $params['oldkeyfile'];
            $oldIsKeyFile = TRUE;
        } else {
            $old = $params['oldpassphrase'];
            $oldIsKeyFile = FALSE;
        }
        if(isset($params['newkeyfile']) && !empty($params['newkeyfile'])) {
            $new = $params['newkeyfile'];
            $newIsKeyFile = TRUE;
        } else {
            $new = $params['newpassphrase'];
            $newIsKeyFile = FALSE;
        }
        // Add the key
        try {
            $luks->addKey($old, $new, $oldIsKeyFile, $newIsKeyFile);
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(gettext("Unable to add the key to the encrypted device: %s"),
                $e->getMessage()));
        }
    }

    /**
     * Change a key in the container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device.
     *     \em devicefile The block special device of the LUKS container to modify.
     *      And containing either passphrase or file fields for old & new:
     *     \em oldpassphrase A current passphrase that will unlock the device.
     *     \em newpassphrase The new passphrase which will replace the old key.
     *     \em oldkeyfile Path to the uploaded key file that unlocks the device.
     *     \em newkeyfile Path to the uploaded key file that replaces the old key.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function changeContainerKey($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.containerkey");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Build the command depending on the mix of passphrases and key files
        if(isset($params['oldkeyfile']) && !empty($params['oldkeyfile'])) {
            $old = $params['oldkeyfile'];
            $oldIsKeyFile = TRUE;
        } else {
            $old = $params['oldpassphrase'];
            $oldIsKeyFile = FALSE;
        }
        if(isset($params['newkeyfile']) && !empty($params['newkeyfile'])) {
            $new = $params['newkeyfile'];
            $newIsKeyFile = TRUE;
        } else {
            $new = $params['newpassphrase'];
            $newIsKeyFile = FALSE;
        }
        // Change the key
        try {
            $luks->changeKey($old, $new, $oldIsKeyFile, $newIsKeyFile);
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(gettext("Unable to change the key on the encrypted device: %s"),
                $e->getMessage()));
        }
    }

    /**
     * Remove a key from a container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device.
     *     \em devicefile The block special device of the LUKS container to modify.
     *      And containing either passphrase or filename/path fields:
     *     \em passphrase The passphrase to remove from the device.
     *     \em keyfile Path to the uploaded key file to unlock the device.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function removeContainerKey($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.removecontainerkey");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Remove the key
        if(isset($params['keyfile']) && !empty($params['keyfile'])) {
            $key = $params['keyfile'];
            $keyIsFile = TRUE;
        } else {
            $key = $params['passphrase'];
            $keyIsFile = FALSE;
        }
        try {
            $luks->removeKey($key, $keyIsFile);
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(gettext("Unable to remove the key from the encrypted device: %s"),
                $e->getMessage()));
        }
    }

    /**
     * Test whether a key unlocks a container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device.
     *     \em devicefile The block special device of the LUKS container to open.
     *      And containing either passphrase or key file fields:
     *     \em passphrase The passphrase to unlock the device.
     *     \em keyfile Path to the uploaded key file to unlock the device.
     * @param context The context of the caller.
     * @return An integer from 0-7 representing which keyslot the
     *          passphrase successfully unlocked, otherwise none.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function testContainerKey($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.opencontainer");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Test the key
        if(isset($params['keyfile']) && !empty($params['keyfile']))
            $slot = $luks->testKey($params['keyfile'], TRUE);
        else
            $slot = $luks->testKey($params['passphrase']);
        if ($slot === FALSE) {
            throw new \OMV\Exception(
              sprintf(gettext("The key did not unlock any key slot on the device")));
        } else {
            return $slot;
        }
    }

    /**
     * Erase (kill) a key slot on the container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device.
     *     \em devicefile The device file of the container to modify.
     *     \em keyslot A number from 0-7 representing which key slot to kill.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function killContainerKeySlot($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.containerkeyslot");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Kill the key slot.
        try {
            $luks->killSlot($params['keyslot']);
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(gettext("Unable to erase the key slot on the encrypted device: %s"),
                $e->getMessage()));
        }
    }

    /**
     * Backup the container header.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     * @param context The context of the caller.
     * @return An array with the following keys:
     *     \em filename Filename of the header backup being downloaded.
     *     \em filepath Location of the temporary file.
     *     \em unlink Whether to delete the temporary file after downloading.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function backupContainerHeader($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.devicefile");
        // Validate the container
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new \OMV\Exception(
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Extract the header to a temporary location and modify the
        // file mode/owner to allow the WebGUI PHP backend to unlink it.
        $tmpFilePath = sys_get_temp_dir()."/".uniqid("luksHeader");
        try {
            $luks->backupHeader($tmpFilePath);
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(
                gettext("Unable to extract the LUKS header from the encrypted device: %s"),
                $e->getMessage()));
        }
        // Adjust header backup temporary file permissions and ownership so
        // that the WebGUI can delete it after downloading.
        chmod($tmpFilePath, 0600);
        chgrp($tmpFilePath, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chown($tmpFilePath, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        // Build filename for file
        $fn = preg_replace('/\s+/',
                           '-',
                            [
                                 $luks->getVendor(),
                                 $luks->getModel(),
                                 $luks->getSerialNumber(),
                                 $luks->getUuid()
                            ]
        );
        // Return values required by generic download RPC implementation.
        return [
            "filename"       => "LUKS_header_".implode('_', $fn).".bak",
            "filepath"       => $tmpFilePath,
            "contenttype"    => "application/octet-stream",
            "unlink"         => TRUE
        ];
    }

    /**
     * Restore the container header.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     *     \em uuid The existing UUID of the encrypted device.
     *     \em force Boolean, whether to proceed even if the UUID from
     *          the backup doesn't match that on the device.
     *     \em filename The original name of the file.
     *     \em filepath The path to the uploaded file.
     * @param context The context of the caller.
     * @return None
     * @throw E_MISC_DEVICE_NOT_FOUND
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function restoreContainerHeader($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.luks.containerheader");
        // Get the storage device object.
        $sd = \OMV\System\Storage\StorageDevice::getStorageDevice($params['devicefile']);
        if (is_null($sd) || !$sd->exists()) {
            throw new \OMV\Exception($params['devicefile']);
        }
        // Get the storage device backend of the given device.
        $mngr = \OMV\System\Storage\Backend\Manager::getInstance();
        $sdb = $mngr->getBackend($sd->getDeviceFile());
        if (is_null($sdb)) {
            throw new \OMV\Exception(sprintf(
                gettext("No storage device backend exists for device %s"),
                $sd->getDeviceFile()));
        }
        // Validate the new header
        $cmd = sprintf("export LANG=C; cryptsetup isLuks %s 2>&1",
                        $params['filepath']);
        if (0 !== $this->exec($cmd, $output)) {
            throw new \OMV\Exception(
                sprintf(gettext("%s is not a valid LUKS header backup file"),
                        $params['filename']));
        }
        // Check the UUIDs match, unless force is set
        if($params['force'] === FALSE) {
            unset($cmd, $output, $result);
            $cmd = sprintf("export LANG=C; cryptsetup luksUUID %s 2>&1",
                $params['filepath']
            );
            $this->exec($cmd, $output);
            $header_uuid = $output[0];
            if($header_uuid !== $params['uuid']) {
                throw new \OMV\Exception(
                    sprintf(gettext("The UUID of the LUKS header backup file ".
                            "doesn't match the device. If you are sure you ".
                            "want to write this header to the device, try ".
                            "again with the 'force' option enabled.".PHP_EOL.
                            "Target device UUID:".PHP_EOL." %s".PHP_EOL.
                            "Header backup UUID:".PHP_EOL." %s"),
                            $params['uuid'],
                            $header_uuid
                           ));
            }
        }
        // Write the header to the device
        $luks = new \OMV\System\Storage\Luks\Container($params['devicefile']);
        try {
            $luks->restoreHeader($params['filepath']);
        } catch(Exception $e) {
            throw new \OMV\Exception(sprintf(
                gettext("Unable to restore the LUKS header to device: %s"),
                $e->getMessage()));
        }
    }
}
