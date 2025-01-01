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
namespace OMV\System\Storage\Luks;

use OMV\System;
use OMV\System\Filesystem\Backend\Manager;
use OMV\System\Process;

/**
 * Class for handling a LUKS-encrypted device (aka a LUKS container).
 */
class Container extends \OMV\System\Storage\StorageDevice {

    /**
     * Notes for cryptsetup:
     * Cryptsetup returns 0 on success and a non-zero value on error.
     * Error codes are:
     *  1 wrong parameters
     *  2 no permission (bad passphrase)
     *  3 out of memory
     *  4 wrong device specified
     *  5 device already exists or device is busy
     */
    protected $uuid         = "";
    protected $isOpen       = FALSE;
    protected $headerInfo   = "";
    protected $usedKeySlots = 0;
    protected $freeKeySlots = 8;

    protected $deviceMapperDeviceFile = "";
    protected $deviceMapperName       = "";

    private $dataCached = FALSE;

    /**
     * Get the name of the device mapper device.
     * @return The name of the device mapper device.
     */
    public function getDeviceMapperName() {
        // Make sure the canonical device file is used to extract the name
        // of the device.
        $path = sprintf("/sys/class/block/%s/dm/name",
                        $this->getDeviceMapperCanonicalName());
        if (!file_exists($path))
            return FALSE;
        return trim(file_get_contents($path));
    }

    /**
     * Get the UUID of the device mapper device.
     * @return The UUID of the device mapper device, otherwise FALSE.
     */
    public function getDeviceMapperUuid() {
        // Make sure the canonical device file is used to extract the name
        // of the device.
        $path = sprintf("/sys/class/block/%s/dm/uuid",
                        $this->getDeviceMapperCanonicalName());
        if (!file_exists($path))
            return FALSE;
        return trim(file_get_contents($path));
    }

    /**
     * Get the holder device file of the container if it's open
     * @return A device file string (/dev/dm-0), otherwise FALSE.
     */
    public function getDeviceMapperDeviceFile() {
        if (FALSE === ($holders = $this->getHolders()))
            return FALSE;
        if (count($holders)!=1)
            return FALSE;
        return $holders[0]; // Should only be one holder, just return the first
    }

    /**
     * Get the holder device name of the container if it's open
     * @return A device name (dm-0), otherwise FALSE.
     */
    public function getDeviceMapperCanonicalName() {
        // Get the device file and extract the name, e.g. /dev/sda => sda.
        if (FALSE === ($dev = $this->getDeviceMapperDeviceFile())) {
            return FALSE;
        }
        $deviceName = str_replace("/dev/", "", $dev);
        return $deviceName;
    }

    /**
     * Get detailed information for the container.
     * @private
     * @return TRUE if successful, otherwise FALSE.
     */
    private function getData() {
        if ($this->dataCached !== FALSE)
            return TRUE;

        // Reset cached data
        $this->uuid                   = "";
        $this->isOpen                 = FALSE;
        $this->headerInfo             = "";
        $this->usedKeySlots           = 0;
        $this->freeKeySlots           = 8;
        $this->deviceMapperDeviceFile = "";
        $this->deviceMapperName       = "";
        $this->LuksVersion            = "";
        $this->LuksLabel              = "";

        // Look up the UUID for the LUKS container
        $cmd = sprintf("cryptsetup luksUUID %s", $this->getDeviceFile());
        $process = new Process($cmd);
        $process->setQuiet();
        $process->execute($output, $exitStatus);
        if ($exitStatus !== 0)
            return FALSE;

        $uuid = trim($output[0]);
        $this->uuid = $uuid;
        unset($cmd, $output, $exitStatus);

        // Get size of device
        $this->size = $this->getSize();

        // Check if the device is open and get the device mapper name if so
        if (FALSE !== ($dev = $this->getDeviceMapperDeviceFile())) {
            // Any devices of the form /dev/dm-n are for internal use only and
            // should never be used. Because of that the device file returned
            // should look like /dev/mapper/<xyz>. See for more information:
            // https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html-single/DM_Multipath
            if (1 == preg_match("/^\/dev\/dm-\d+$/", $dev)) {
                if (FALSE !== ($name = $this->getDeviceMapperName())) {
                    $this->deviceMapperDeviceFile = sprintf("/dev/mapper/%s",
                                                            $name);
                    $this->deviceMapperName = $name;
                } else {
                    $this->deviceMapperDeviceFile = $dev;
                }
            }
            $this->isOpen = TRUE;
        }

        // Collect the detailed output from luksDump
        $cmd = sprintf("cryptsetup luksDump %s", $this->getDeviceFile());
        $process = new Process($cmd);
        $process->execute($output, $exitStatus);
        $this->headerInfo = $output;

        $version = explode(':',preg_replace('/\s/','',implode('', preg_grep("/^Version:/", $this->headerInfo))))[1];
        $this->luksVersion = $version;
        
        switch ($version) {
            case 2:
                $label_line = implode( preg_grep( "/^Label:/", $this->headerInfo ) );
                $label = preg_replace( '/^\s+/', '' , explode( ':' , $label_line )[1] );
                if ("(no label)" == $label)  {
                    $this->luksLabel = "";
                } else {
                    $this->luksLabel = $label;
                }
                break;
            default:
                $this->luksLabel = "n/a";
                break;
        }


        if ($version == "1") {
            $this->usedKeySlots = count(preg_grep("/^Key Slot \d: ENABLED$/",
                                                 $this->headerInfo));
        } elseif ($version == "2" ) {
            $this->usedKeySlots = count(preg_grep("/^\s+(\d:\s)(luks2)/",
                                                $this->headerInfo));
        }

        $this->freeKeySlots = count(preg_grep("/^Key Slot \d: DISABLED$/",
                                                $this->headerInfo));

        // Set flag to mark information has been successfully read.
        $this->dataCached = TRUE;

        return TRUE;
    }

    /**
     * Refresh the cached information.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function refresh() {
        $this->dataCached = FALSE;
        if ($this->getData() === FALSE)
            return FALSE;
        return TRUE;
    }

    /**
     * Checks if the container exists - synonym for isLuks().
     * @return TRUE if the container exists, otherwise FALSE.
     */
    public function exists() {
        return $this->isLuks();
    }

    /**
     * Checks if the device exists and is a LUKS container
     * @return TRUE if the device is a LUKS container, otherwise FALSE.
     */
    public function isLuks() {
        if (FALSE === parent::exists())
            return FALSE;
        return self::isLuksContainer($this->getDeviceFile());
    }

    /**
     * Helper function for determining if a device is a LUKS container.
     * @return TRUE if the device is a LUKS container, otherwise FALSE.
     */
    public static function isLuksContainer($deviceFile) {
        // TODO: would it be better (quicker) to check the UUID
        // in, e.g., /sys/class/block/dm-0/dm/uuid (it begins
        // with 'CRYPTO' for LUKS/dm-crypt devices)?
        $cmd = sprintf("cryptsetup isLuks %s", escapeshellarg($deviceFile));
        $process = new Process($cmd);
        $process->setQuiet();
        $process->execute($output, $exitStatus);
        if (0 !== $exitStatus)
            return FALSE;
        return TRUE;
    }

    /**
     * Get the holder devices of the LUKS container (i.e. the
     * decrypted device, if open).
     * @return An array of device files, otherwise FALSE.
     */
    public function getHolders() {
        // Make sure the canonical device file is used to extract the name
        // of the device.
        $path = sprintf("/sys/class/block/%s/holders",
            $this->getDeviceName(TRUE));
        if (!file_exists($path))
            return FALSE;
        $result = [];
        $dir = new \DirectoryIterator($path);
        foreach ($dir as $item) {
            if ($item->isDot() || !$item->isLink())
                continue;
            $result[] = sprintf("/dev/%s", $item->getFilename());
        }
        return $result;
    }

    /**
     * Get detailed information about the container.
     * @return Detailed information about the container, FALSE on failure.
     */
    public function getDetail() {
        if ($this->getData() === FALSE)
            return FALSE;
        return implode("\n", $this->headerInfo);
    }

    /**
     * How many key slots are used.
     * @return Number of used key slots, FALSE on failure.
     */
    public function getUsedKeySlots() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->usedKeySlots;
    }


    /**
     * Version of luks.
     * @return version number of luks.
     */
    public function getLuksVersion() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->luksVersion;
    }

    /**
     * Label of luks container.
     * @return label string of luks.
     */
    public function getLuksLabel() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->luksLabel;
    }

    /**
     * How many key slots are unused.
     * @return Number of free key slots, FALSE on failure.
     */
    public function getFreeKeySlots() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->freeKeySlots;
    }

    /**
     * Get the UUID of the container.
     * @return The UUID of the container, FALSE on failure.
     */
    public function getUuid() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->uuid;
    }

    /**
     * Is the container open? (i.e. unlocked and mapped).
     * @return TRUE if the container is open, otherwise FALSE.
     */
    public function isOpen() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->isOpen;
    }

    /**
     * Get the devicefile of the mapped device (i.e. the open container).
     * @return The mapped devicefile of the container, FALSE on failure.
     */
    public function getDecryptedDeviceFile() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->deviceMapperDeviceFile;
    }

    /**
     * Get the device name of the mapped device (i.e. the open container).
     * @return The mapped device name of the container, FALSE on failure.
     */
    public function getDecryptedName() {
        if ($this->getData() === FALSE)
            return FALSE;
        return $this->deviceMapperName;
    }

    /**
     * Helper function for determining a name for the decrypted device.
     * Avoids naming problems with, e.g. LUKS-on-LVM where the devicefile
     * is of the form /dev/mapper/VG-LV.
     * @return A sanitised string for use as the mapped device name.
     */
    private function generateDecryptedName() {
        $dev = $this->getDeviceName();
        $dev = preg_replace("/^mapper\//", "", $dev);
        return str_replace("/", "-", $dev);
    }

    /**
     * Get the description of the LUKS container.
     * @return The LUKS container description, FALSE on failure.
     */
    public function getDescription() {
        if ($this->getData() === FALSE)
            return FALSE;
        return sprintf(gettext("LUKS encrypted device %s[%s, %s]"),
            ($this->getModel()) ? '('.$this->getModel().') ' : '',
            $this->getDeviceFile(),
            binary_format($this->getSize()));
    }

    /**
     * Create the container.
     * @param devicefile The device file where to create the LUKS container.
     * @param key A passphrase or key file (see following)
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @param cipher Method of encryption to be used when formatting the device
     * @param label Optional. String to tag the block device
     * @return TRUE if successful, otherwise FALSE.
     */
    public function create($key, $keyIsFile=FALSE, $cipher, $label) {
        if (TRUE === $keyIsFile) {
            $cmd = sprintf("cryptsetup luksFormat --label=%s -c %s -q %s %s",
                $label,
                $cipher,
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($key));
        } else {
            $cmd = sprintf("echo -n %s | cryptsetup luksFormat --label=%s -c %s -q %s",
                escapeshellarg($key),
                $label,
                $cipher,
                escapeshellarg($this->getDeviceFile()));
        }
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output);
        $this->refresh();
        return TRUE;
    }

    /**
     * Remove the container.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function remove() {
        // First, close the device if it is open
        if ($this->isOpen()) {
            if (FALSE === $luks->close()) {
                return FALSE;
            }
        }
        // Get the payload offset (header size)
        $cmd = sprintf("cryptsetup luksDump %s ".
            "| grep 'Payload offset' | awk '{print $3}'",
            escapeshellarg($this->getDeviceFile()));

        $process = new Process($cmd);
        $process->setQuiet();
        $process->execute($output, $exitStatus);
        if (0 !== $exitStatus) {
            $header_size = 4096;
        } else {
            $header_size = trim($output[0]);
        }
        if (intval($header_size) <= 0) {
            $header_size = 4096;
        }
        unset($cmd, $output, $exitStatus);

        // Get the storage device object.
        $sd = \OMV\System\Storage\StorageDevice::getStorageDevice(
            $this->getDeviceFile());
        if (is_null($sd) || !$sd->exists()) {
            throw new \OMV\Exception("No storage device for %s",
                $this->getDeviceFile());
        }
        // Get the storage device backend of the given device.
        $mngr = \OMV\System\Storage\Backend\Manager::getInstance();
        $sdb = $mngr->getBackend($sd->getDeviceFile());
        if (is_null($sdb)) {
            throw new \OMV\Exception("No storage backend for %s",
                $this->getDeviceFile());
        }
        switch ($sdb->getType()) {
            case OMV_STORAGE_DEVICE_TYPE_SOFTWARERAID:
            case OMV_STORAGE_DEVICE_TYPE_DEVICEMAPPER:
                // Wipe existing filesystems.
                $cmd = sprintf("wipefs -a %s",
                    escapeshellarg($sd->getDeviceFile()));
                break;
            default:
                // Wipe existing filesystems.
                $cmd = sprintf("sgdisk --zap-all %s",
                    escapeshellarg($sd->getDeviceFile()));
                break;
        }
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        unset($cmd, $output, $exitStatus);

        // Destroy the header by overwriting it
        $cmd = sprintf("dd if=/dev/urandom of=%s bs=512 count=%s",
            escapeshellarg($sd->getDeviceFile()),
            escapeshellarg($header_size));
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        $this->refresh();
        return TRUE;
    }

    /**
     * Open (unlock) the container.
     * @param key A passphrase or key file (see following) which will unlock
     *            the LUKS container.
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     * TODO: change from using [dev]-crypt as the mapper name to the UUID of
     *       container instead (unique, probably will be needed for crypttab)
     */
    public function open($key, $keyIsFile = FALSE) {
        if (TRUE === $keyIsFile) {
            $cmd = sprintf("cryptsetup luksOpen %s %s-crypt --key-file %s",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($this->generateDecryptedName()),
                escapeshellarg($key));
        } else {
            $cmd = sprintf("echo -n %s | ".
                "cryptsetup luksOpen %s %s-crypt --key-file=-",
                escapeshellarg($key),
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($this->generateDecryptedName()));
        }
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        $this->refresh();
        return TRUE;
    }

    /**
     * Close (lock) the container.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function close() {
        $cmd = sprintf("cryptsetup luksClose %s",
            escapeshellarg($this->getDecryptedName()));
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        $this->refresh();
        return TRUE;
    }

    /**
     * Add a key to the container.
     * @param old A passphrase or key file (see following) that unlocks the device.
     * @param new A passphrase or key file (see following) to add to the device.
     * @param oldIsFile Optional. A boolean indicating whether the param 'old'
     *                  is a passphrase (FALSE, in which case old is a string),
     *                  or a key file (TRUE, in which case old is a filepath to
     *                  the key file). Defaults to FALSE.
     * @param newIsFile Optional. A boolean indicating whether the param 'new'
     *                  is a passphrase (FALSE, in which case new is a string),
     *                  or a key file (TRUE, in which case new is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function addKey($old,
                           $new,
                           $oldIsFile = FALSE,
                           $newIsFile = FALSE) {
        // Build command line
        if (TRUE === $oldIsFile) {
            $cmd = sprintf("cryptsetup luksAddKey -q %s -d %s ",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($old));
        } else {
            $cmd = sprintf("echo -n %s | cryptsetup luksAddKey -q " . " %s ",
                escapeshellarg($old),
                escapeshellarg($this->getDeviceFile()));
        }
        if (TRUE === $newIsFile) {
            $cmd .= escapeshellarg($new);
        } else {
            $cmd .= sprintf(" <(echo -n %s)", escapeshellarg($new));
            // N.B. Need to use bash rather than default sh here for
            // process substitution method of injecting new passphrase
            $cmd = sprintf("/bin/bash -c '%s'", $cmd);
        }
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        $this->refresh();
        return TRUE;
    }

    /**
     * Change a key that unlocks the container.
     * @param old A passphrase or key file (see following) that unlocks the device.
     * @param new The passphrase or key file (see following) to replace the old one.
     * @param oldIsFile Optional. A boolean indicating whether the param 'old'
     *                  is a passphrase (FALSE, in which case old is a string),
     *                  or a key file (TRUE, in which case old is a filepath to
     *                  the key file). Defaults to FALSE.
     * @param newIsFile Optional. A boolean indicating whether the param 'new'
     *                  is a passphrase (FALSE, in which case new is a string),
     *                  or a key file (TRUE, in which case new is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function changeKey($old,
                              $new,
                              $oldIsFile = FALSE,
                              $newIsFile = FALSE) {
        // Build command line
        if (TRUE === $oldIsFile) {
            $cmd = sprintf("cryptsetup luksChangeKey -q ".
                "%s --key-file %s ",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($old));
        } else {
            $cmd = sprintf("echo -n %s | cryptsetup luksChangeKey -q ".
                " %s --key-file=- ",
                escapeshellarg($old),
                escapeshellarg($this->getDeviceFile()));
        }
        if (TRUE === $newIsFile) {
            $cmd .= escapeshellarg($new);
        } else {
            $cmd .= sprintf("<(echo -n %s)", escapeshellarg($new));
            // N.B. Need to use bash rather than default sh here for
            // process substitution method of injecting new passphrase
            $cmd = sprintf("/bin/bash -c '%s'", $cmd);
        }
        // Execute
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        $this->refresh();
        return TRUE;
    }

    /**
     * Remove a key from the container.
     * @param key The passphrase or key file (see following) to remove.
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function removeKey($key, $keyIsFile=FALSE) {
        if (TRUE === $keyIsFile) {
            $cmd = sprintf("cryptsetup luksRemoveKey -q %s --key-file %s",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($key));
        } else {
            $cmd = sprintf("/bin/bash -c 'echo -n %s | ".
                "cryptsetup luksRemoveKey -q %s --key-file=-'",
                escapeshellarg($key),
                escapeshellarg($this->getDeviceFile()));
        }
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        $this->refresh();
        return TRUE;
    }

    /**
     * Erase (kill) a key slot - remove a key from the
     * container without knowing it (cf. removeKey)
     * @param slot A number from 0-7 representing which key slot to erase
     * @return TRUE if successful, otherwise FALSE.
     */
    public function killSlot($slot) {
        // Use batch mode to avoid needing a key - note this
        // makes it trivial to kill the last slot without warning!
        $cmd = sprintf("cryptsetup -q luksKillSlot %s %s",
            escapeshellarg($this->getDeviceFile()),
            escapeshellarg($slot));
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        $this->refresh();
        return TRUE;
    }

    /**
     * Test whether a key will open the container.
     * @param key A passphrase or key file (see following) to test.
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return An integer from 0-7 representing which key slot the
     *         key matched (unlocked), otherwise FALSE.
     */
    public function testKey($key, $keyIsFile=FALSE) {
        if (TRUE === $keyIsFile) {
            $cmd = sprintf("cryptsetup luksOpen -v ".
                "--test-passphrase %s --key-file %s",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($key));
        } else {
            $cmd = sprintf("/bin/bash -c 'echo -n %s | ".
                "cryptsetup luksOpen -v --test-passphrase %s --key-file=-'",
                escapeshellarg($key),
                escapeshellarg($this->getDeviceFile()));
        }

        // Test the key and get the key slot number if successful
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output, $exitStatus);
        if ($exitStatus !== 0) {
            throw new \OMV\Exception($output);
        }
        $slot = explode(" ", $output[0])[2];
        // Return which key slot was unlocked.
        return $slot;
    }

    /**
     * Backup the header for the container.
     * @param filepath The filename to write the header backup to.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function backupHeader($filepath) {
        $cmd = sprintf("cryptsetup luksHeaderBackup %s --header-backup-file %s",
            escapeshellarg($this->getDeviceFile()),
            escapeshellarg($filepath));
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output,$exitStatus);
        return TRUE;
    }

    /**
     * Restore the header for the container from a backup.
     * @param filepath The path to the header backup file to restore.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function restoreHeader($filepath) {
        $cmd = sprintf("cryptsetup luksHeaderRestore -q ".
                        "%s --header-backup-file %s",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($filepath));
        $process = new Process($cmd);
        $process->setRedirect2to1();
        $process->execute($output,$exitStatus);
        $this->refresh();
        return TRUE;
    }
}
