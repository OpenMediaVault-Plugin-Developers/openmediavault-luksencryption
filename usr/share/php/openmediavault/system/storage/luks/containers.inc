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

/**
 * Class for handling LUKS-encrypted disks.
 */
class Containers {
    /**
     * Enumerate LUKS devices.
     * @return A list of devices that are LUKS containers, otherwise FALSE.
     * Example: array(
     *     0 => /dev/sdb
     *     1 => /dev/sdd
     * )
     */
    public static function enumerate() {
        $cmd = "blkid -t TYPE=crypto_LUKS -o device";
        $process = new \OMV\System\Process($cmd);
        $process->setQuiet();
        $process->execute($output, $exitStatus);
        $list = [];
        if ($exitStatus == 0) {
            // Parse command output:
            //   /dev/sdc
            //   /dev/sdd
            //   unknown device
            foreach ($output as $outputk => $outputv) {
                $deviceFile = trim($outputv);
                if (!is_devicefile($deviceFile))
                    continue;
                $list[] = $deviceFile;
            }
        }
        return $list;
    }
}
