$(document).ready(function() {
    
    $('body.step2 select[name=category]').change(function() {

        // Set category name strings
        $('span.category_name').text($(this).val());

        // Uncheck all checkboxes
        $('#jobs>div input[type=checkbox]').prop('checked', false);

        // Filter job checkboxes
        var matching = $('#jobs>div').filter('.cat-' + $(this).val());
        var nonmatching = $('#jobs>div').not('.cat-' + $(this).val());

        // Show filtered jobs
        if ($('#jobs').hasClass('hidden')) {
            $('#jobs').removeClass('hidden');
            matching.show();
            nonmatching.hide();
        } else {
            matching.show('fast');
            nonmatching.hide('fast');
        }

    });
});
