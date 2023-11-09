=== RingCentral Communications Plugin - FREE ===
Contributors:      pbmacintyre
Tags:              Ring Central Communications API tools
Requires at least: 6.3.0
Tested up to:      6.4.1
Stable tag:        1.5.4
Requires PHP:      8.0.2
License:           GPLv2 or later
License URI:       https://www.gnu.org/licenses/gpl-2.0.html

This plugin allows for the use of the RingCentral communication tools platform based on the RingCentral PHP API.

This plugin makes calls to: https://ringcentral.github.io/ringcentral-embeddable-voice/adapter.js

The embeddable code base is here: https://github.com/ringcentral/ringcentral-embeddable

The license is here: https://github.com/ringcentral/ringcentral-js-widgets/blob/master/LICENSE

This is an out-of-the-box embeddable web phone app that helps developers to integrate RingCentral services into their own web applications. This is controlable in the settings page with a check box to turn it on or off. There is also a Team Messaging component added in version 1.4

== Description ==

This plugin allows for the use of the RingCentral communication tools platform based on the RingCentral PHP API.

This plugin makes calls to: https://ringcentral.github.io/ringcentral-embeddable-voice/adapter.js

The embeddable code base is here: https://github.com/ringcentral/ringcentral-embeddable

The license is here: https://github.com/ringcentral/ringcentral-js-widgets/blob/master/LICENSE

This is an out-of-the-box embeddable web phone app that helps developers to integrate RingCentral services
into their own WordPress installations. This is controllable in the settings page with a checkbox to turn it on or off.

= Features =

<ul>
<li>RingCentral Embedded Phone app - 
RingCentral's embedded phone app can be turned on or off and calls can be made from within the WordPress Admin area.
</li>

<li>Call Me Request widget - 
Feature for adding a Call Me request Widget to the sidebar on the public side of your WordPress installation. This allows Website
visitors to call you (using the RingCentral RingOut feature) and if no one is on-line to answer the request will be stored on the admin side.
</li>

<li>Newsletter Sign Up widget - 
Feature for adding a Newsletter (New Post) signup Widget to the sidebar on the public side of your WordPress installation.
Asking for both or one of email address and mobile number as communication points (double opt-in).
</li>

<li>New Newsletter (Post) announcements - 
Based on configuration settings, you can send out automatic announcements to your collected newsletter list based on their
provided (double opt-in) contact information: email and / or mobile.
</li>

<li>Manually add subscribers - 
Feature to manually add to your list of Newsletter announcement subscribers with name email and mobile number. The new subscriber
will still have to opt-in to the list.
</li>

<li>List / Manage subscribers - 
Feature to display your existing list of Newsletter announcement subscribers. You can delete individually or collectively.
There is no edit feature as changes will need to be initiated by the subscriber and re-validated via the opt-in process.
</li>

<li>List / Manage Call Me Requests -  
Feature to display your existing list of Call Me requests. You can delete individually or collectively. List shows caller
name, phone number to call back, and reason for the call.
</li>

<li>Default pages are created for you to customize -
Default WordPress pages are created upon activation of the plugin. A very basic confirmation email page is provided.
A basic page for confirming opt-out requests is also provided. Page names are: 'eMail Confirmation' & 'eMail Unsubscribe'.
NOTE: permainks must be set to "Post name"
</li>

<li>New Database tables are created - 
New tables are created in the database and seeded with basic starting data in order for the plugin to operate correctly.
All table names are prefixed by 'ringcentral_'. The plugin drops these tables if the plugin is ever deleted, so be sure
to save any data if you ever plan on deleting the plugin.
</li>

</ul>

== Installation ==
Use WordPress' Add New Plugin feature, searching "RingCentral Free", or download the archive and:
1. Unzip the archive on your computer
2. Upload `RingCentral-Free` directory to the '/wp-content/plugins/' directory
3. Activate the plugin through the 'Plugins' menu in WordPress
4. New menu item should appear in the 'Admin' top level menu

== Frequently Asked Questions ==
= Do I need a Ring Central Developer account =
Currently, yes. We are working on another edition that will allow for account only holders to make 
use of this plug in, but currently you do need to have a developer account. 

== Screenshots ==
1. Plugin installation selection
2. Plugin added to admin menu "RingCentral"
3. Plugin Configuration Settings page
4. Plugin manually add new subscriber admin page
5. Plugin Manage subscribers admin page
6. Plugin widget selection page
7. Plugin widgets added to selected sidebar
8. Plugin "Call Me Request" sidebar widget on public side
9. Plugin "Newsletter Sign Up" sidebar widget on public side
10. Email opt-in confirmation page, editable
11. Email opt-out confirmation page, editable
12. SMS 2FA User profile editing page - part 1
13. SMS 2FA User profile editing page - part 2
14. SMS 2FA User profile editing page - part 3
15. 2FA challenge screen on admin login
16. JWT Creation screen on RingCentral Developers consol
17. JWT Code information after key creation

== Changelog ==
= 1.0 =
* Initial version
= 1.4.2 =
* Updated User Guide with Appendix A - Guide to create app on RingCentral Developers site.
= 1.4.5 =
* Ensured compatability with WordPress 5.8.1. 
= 1.5 =
* Ensured compatability with WordPress 6.3.1.
* Added 2FA SMS 6 digit code admin validation to login process and user profiles

== Upgrade Notice ==
== Contribute ==
If you find this useful and if you want to contribute, here are some ways:
1. You can [write me](https://paladin-bs.com/contact) and submit your bug reports or improvement suggestions;