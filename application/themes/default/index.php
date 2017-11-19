<?php echo theme_view('header'); ?>
<div class="container"><!-- Start of Main Container -->
    <?php

    echo Template::message();
    echo isset($content) ? $content : Template::content();

    echo theme_view('footer');
    ?>
