 // Register FilePond plugins
 FilePond.registerPlugin(
    FilePondPluginImagePreview,
    FilePondPluginImageResize,
    FilePondPluginFileEncode,
    FilePondPluginImageCrop
);

// Set FilePond options
FilePond.setOptions({
    
    stylePanelAspectRatio: 200 / 200,
    imageResizeTargetWidth: 250,
    imageResizeTargetHeight: 250,
    stylePanelLayout: 'circle',
    server: {
        server: '/upload',
    }
   
});

// Create FilePond instance
const inputElement = document.querySelector('input[type="file"]');
const pond = FilePond.create(inputElement);

// Parse FilePond elements
FilePond.parse(document.body);