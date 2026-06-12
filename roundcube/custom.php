<?php
// The mailserver uses a self-signed certificate; Roundcube talks to it
// only over the internal docker network, so skip peer verification.
$config['imap_conn_options'] = [
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ],
];
$config['smtp_conn_options'] = $config['imap_conn_options'];
