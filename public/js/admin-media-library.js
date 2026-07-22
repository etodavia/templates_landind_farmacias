(function () {
    let activeInput = null;
    let mediaItems = [];

    function targetFieldName(fileInput) {
        const name = fileInput.name || '';
        let match = name.match(/^promotional_banner_(\d+)_file$/);
        if (match) return `promotional_banner_${match[1]}_image`;
        match = name.match(/^hero_carousel_(desktop|tablet|mobile)_(\d+)_file$/);
        if (match) return `carousel_${match[1]}_${match[2]}`;
        return name.endsWith('_file') ? name.slice(0, -5) : name;
    }

    function ensureTargetInput(fileInput) {
        const fieldName = targetFieldName(fileInput);
        const form = fileInput.form;
        if (!form || !fieldName) return null;
        let target = Array.from(form.querySelectorAll('input[type="hidden"]')).find(input => input.name === fieldName);
        if (!target) {
            target = document.createElement('input');
            target.type = 'hidden';
            target.name = fieldName;
            fileInput.insertAdjacentElement('afterend', target);
        }
        return target;
    }

    function createModal() {
        const modal = document.createElement('div');
        modal.id = 'adminMediaPicker';
        modal.className = 'media-picker-overlay';
        modal.innerHTML = `<div class="media-picker-dialog" role="dialog" aria-modal="true" aria-label="Banco de Mídias"><div class="media-picker-header"><div><strong>Banco de Mídias</strong><small>Escolha uma imagem já enviada</small></div><button type="button" class="media-picker-close" aria-label="Fechar"><i class="ri-close-line"></i></button></div><div class="media-picker-search"><i class="ri-search-line"></i><input type="search" placeholder="Buscar pelo nome do arquivo..."></div><div class="media-picker-grid"></div><div class="media-picker-empty" hidden>Nenhuma imagem encontrada.</div></div>`;
        document.body.appendChild(modal);
        modal.querySelector('.media-picker-close').addEventListener('click', closeModal);
        modal.addEventListener('click', event => { if (event.target === modal) closeModal(); });
        modal.querySelector('input[type="search"]').addEventListener('input', event => renderItems(event.target.value));
        return modal;
    }

    function renderItems(search = '') {
        const modal = document.getElementById('adminMediaPicker');
        const grid = modal.querySelector('.media-picker-grid');
        const empty = modal.querySelector('.media-picker-empty');
        const query = search.trim().toLocaleLowerCase('pt-BR');
        const filtered = mediaItems.filter(item => item.name.toLocaleLowerCase('pt-BR').includes(query));
        grid.innerHTML = '';
        filtered.forEach(item => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'media-picker-item';
            button.title = item.name;
            const img = document.createElement('img');
            img.src = item.url;
            img.alt = item.name;
            img.loading = 'lazy';
            const name = document.createElement('span');
            name.textContent = item.name;
            button.append(img, name);
            button.addEventListener('click', () => selectMedia(item));
            grid.appendChild(button);
        });
        empty.hidden = filtered.length !== 0;
    }

    async function openModal(fileInput) {
        activeInput = fileInput;
        const modal = document.getElementById('adminMediaPicker') || createModal();
        modal.classList.add('open');
        document.body.style.overflow = 'hidden';
        const grid = modal.querySelector('.media-picker-grid');
        grid.innerHTML = '<div class="media-picker-loading"><i class="ri-loader-4-line"></i> Carregando imagens...</div>';
        try {
            const response = await fetch('/admin/api/midias', { headers: { Accept: 'application/json' } });
            if (!response.ok) throw new Error('Não foi possível carregar as imagens.');
            mediaItems = await response.json();
            renderItems();
            modal.querySelector('input[type="search"]').focus();
        } catch (error) {
            grid.innerHTML = `<div class="media-picker-loading">${error.message}</div>`;
        }
    }

    function closeModal() {
        document.getElementById('adminMediaPicker')?.classList.remove('open');
        document.body.style.overflow = '';
    }

    function selectMedia(item) {
        if (!activeInput) return;
        const target = ensureTargetInput(activeInput);
        if (!target) return;
        target.value = item.url;
        activeInput.value = '';
        activeInput.required = false;
        let status = activeInput.parentElement.querySelector('.media-selected-status');
        if (!status) {
            status = document.createElement('div');
            status.className = 'media-selected-status';
            activeInput.parentElement.appendChild(status);
        }
        status.innerHTML = '';
        const preview = document.createElement('img');
        preview.src = item.url;
        preview.alt = '';
        const text = document.createElement('span');
        text.textContent = `Selecionada: ${item.name}`;
        status.append(preview, text);
        const pagePreview = document.getElementById('imgPreview');
        if (pagePreview && activeInput.id === 'fileInput') pagePreview.src = item.url;
        closeModal();
    }

    function enhanceFileInputs() {
        document.querySelectorAll('input[type="file"][accept*="image"]').forEach(input => {
            if (input.dataset.mediaPickerReady) return;
            input.dataset.mediaPickerReady = '1';
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'media-picker-trigger';
            button.innerHTML = '<i class="ri-gallery-line"></i> Escolher do Banco de Mídias';
            button.addEventListener('click', () => openModal(input));
            input.insertAdjacentElement('afterend', button);
        });
    }

    document.addEventListener('DOMContentLoaded', enhanceFileInputs);
    new MutationObserver(enhanceFileInputs).observe(document.documentElement, { childList: true, subtree: true });
})();
