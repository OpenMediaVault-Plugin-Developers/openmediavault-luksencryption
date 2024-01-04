<?php
/**
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    Volker Theile <volker.theile@openmediavault.org>
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2015 Volker Theile
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

 class OMVModuleLuks extends \OMV\Engine\Module\ServiceAbstract
    implements \OMV\Engine\Notify\IListener, \OMV\Engine\Module\INotification {
    /**
     * Get the module name.
     */
    public function getName() {
        return "luks";
    }

    /**
     * Defines the modules that if present should start before the service
     * provided by this module.
     * @return An array of modules.
     */
    public function shouldStart() { return [ "email" ]; }


    /**
     * Get the notification configuration.
     */
    public function getNotificationConfig() {
        return [
            [
                "id"    => "luks",
                "type"  => getText("Storage"),
                "title" => gettext("Encryption")
            ]
        ];
    }

    /**
     * Bind listeners.
     */
    function bindListeners(\OMV\Engine\Notify\Dispatcher $dispatcher) {
        $dispatcher->addListener(
            OMV_NOTIFY_CREATE | OMV_NOTIFY_MODIFY | OMV_NOTIFY_DELETE,
            "org.openmediavault.system.storage.luks.container",
            [ $this, "setDirty" ]);
        $dispatcher->addListener(
            OMV_NOTIFY_MODIFY,
            "org.openmediavault.conf.system.notification.email",
            [ $this, "setDirty" ]);
        $dispatcher->addListener(
            OMV_NOTIFY_MODIFY,
            "org.openmediavault.conf.system.notification.notification",
            [ $this, "setDirty" ]);
    }
}
