<?php
/**
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    Volker Theile <volker.theile@openmediavault.org>
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2016 Volker Theile
 * @copyright Copyright (c) 2015-2024 OpenMediaVault Plugin Developers
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
namespace OMV\System\Storage\Backend;

/**
 * Implements the storage device backend for (open) LUKS containers.
 */
class LUKS extends DM
{
    function enumerate() {
        $devs = parent::enumerate();
        if (FALSE === $devs)
            return FALSE;
        $result = [];
        foreach ($devs as $devk => $devv) {
            // Check if the given device is a LUKS container.
            $object = $this->getImpl($devv);
            if (!$object->exists())
                continue;
            $result[] = $object->getDeviceFile();
        }
        return $result;
    }

    function isTypeOf($deviceFile) {
        // Check if the given device is of type device mapper.
        if (FALSE === parent::isTypeOf($deviceFile))
            return FALSE;
        // Check if it is an open LUKS container.
        $object = new \OMV\System\Storage\StorageDeviceLuks($deviceFile);
        return $object->isLuks();
    }

    function getImpl($args) {
        return new \OMV\System\Storage\StorageDeviceLuks($args);
    }
}
