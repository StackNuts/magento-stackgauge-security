/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */
define([
    'jquery',
    'Magento_Ui/js/modal/alert',
    'jquery/ui'
], function ($, alert) {
    'use strict';

    $.widget('stacknuts.fetchStackGaugeSignatures', {
        options: {
            url: '',
            elementId: ''
        },

        _create: function () {
            this._on({
                click: this._fetch
            });
        },

        _fetch: function () {
            var resultEl = $('#' + this.options.elementId + '_result');

            resultEl.text($.mage.__('Fetching...'));

            $.ajax({
                url: this.options.url,
                type: 'post',
                dataType: 'json',
                showLoader: true,
                data: {
                    form_key: window.FORM_KEY
                }
            }).done(function (response) {
                resultEl.text(response.message);

                if (!response.success) {
                    alert({
                        content: response.message
                    });
                }
            }).fail(function () {
                var message = $.mage.__('Could not reach the server to run this fetch.');

                resultEl.text(message);
                alert({
                    content: message
                });
            });
        }
    });

    return $.stacknuts.fetchStackGaugeSignatures;
});
