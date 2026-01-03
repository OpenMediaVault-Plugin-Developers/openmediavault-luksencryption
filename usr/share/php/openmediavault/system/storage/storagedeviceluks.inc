<?php
/**
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    Volker Theile <volker.theile@openmediavault.org>
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2015 Volker Theile
 * @copyright Copyright (c) 2015-2026 openmediavault plugin developers
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
namespace OMV\System\Storage;

/**
 * Class for handling an open LUKS container,
 * i.e. from the decrypted device point of view.
 */
class StorageDeviceLuks extends StorageDeviceDM {

    public function getLuksEncryptedDeviceFile() {
        if(FALSE === ($slaves = $this->getSlaves()))
            return FALSE;
        if(count($slaves)!=1)
            return FALSE;
        return $slaves[0];  // Should only be one slave, just return the first
    }

     /**
     * Get the canonical device file, e.g. /dev/disk/by-label/root -> /dev/sda
     * @return A device file string (/dev/sda), otherwise FALSE.
     */
    public function getCanonicalLuksEncryptedDeviceFile() {
        if(FALSE === ($dev = $this->getLuksEncryptedDeviceFile()))
            return FALSE;
        return realpath($dev);
    }

    /**
     * Get the base (slave) device name of the container
     * @param canonical If set to TRUE the canonical device file will
     *   be used. Defaults to FALSE.
     * @return A device name (sdb), otherwise FALSE.
     */
    public function getLuksEncryptedDeviceName($canonical = FALSE) {
        $deviceName = str_replace("/dev/", "", !$canonical ?
                                  $this->getLuksEncryptedDeviceFile() :
                                  $this->getCanonicalLuksEncryptedDeviceFile());
        return $deviceName;
    }

    /**
     * Get the container (encrypted device) that backs
     * (i.e. is the slave of) this decrypted (open) device
     * @return An Container object
     */
    public function getContainer() {
        return new \OMV\System\Storage\Luks\Container($this->getLuksEncryptedDeviceFile());
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
        if(FALSE === ($dev = $this->getLuksEncryptedDeviceFile()))
            return FALSE;
        // Test whether the slave is a LUKS container or not
        return \OMV\System\Storage\Luks\Container::isLuksContainer($dev);
    }

    /**
     * Get the underlying device model.
     * @return The device model, otherwise an empty string.
     */
    public function getModel() {
        if(FALSE === ($luks = $this->getContainer()))
            return "";
        return $luks->getModel();
    }

    /**
     * Get the description of the LUKS container.
     * @return The LUKS container description, FALSE on failure.
     */
    public function getDescription() {
        $model = $this->getModel();
        return sprintf("LUKS encrypted container on %s %s[%s, %s]",
            $this->getCanonicalLuksEncryptedDeviceFile(),
            ($model) ? '('.$model.') ' : '',
            $this->getDeviceFile(),
            binary_format($this->getSize()));
    }
}
