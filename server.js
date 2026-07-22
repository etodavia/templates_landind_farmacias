const express = require('express');
const jwt = require('jsonwebtoken');
const pool = require('./config/db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const compression = require('compression');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');

dotenv.config();
const ASSET_VERSION = process.env.ASSET_VERSION || require('./package.json').version || '1';
const ALLOWED_UPLOAD_MIMES = new Set([
    'image/jpeg',
    'image/png',
    'image/webp',
    'image/gif',
    'image/svg+xml',
    'application/pdf'
]);

function parseCookies(cookieHeader = '') {
    return cookieHeader.split(';').reduce((cookies, pair) => {
        const index = pair.indexOf('=');
        if (index === -1) return cookies;
        const key = pair.slice(0, index).trim();
        const value = pair.slice(index + 1).trim();
        if (!key) return cookies;
        try {
            cookies[key] = decodeURIComponent(value);
        } catch (e) {
            cookies[key] = value;
        }
        return cookies;
    }, {});
}

function createRateLimiter({ windowMs, max, message }) {
    const attempts = new Map();
    return (req, res, next) => {
        const now = Date.now();
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const current = attempts.get(ip) || [];
        const recent = current.filter(timestamp => now - timestamp < windowMs);
        if (recent.length >= max) {
            return res.status(429).json({ msg: message });
        }
        recent.push(now);
        attempts.set(ip, recent);
        next();
    };
}

function requireApiAuth(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ msg: 'Autenticacao necessaria.' });
    }
    next();
}

function getTabFromReferer(req) {
    try {
        const referer = req.get('referer');
        if (!referer) return '';
        const url = new URL(referer);
        return url.searchParams.get('tab') || '';
    } catch (e) {
        return '';
    }
}

function cmsRedirect(req, status) {
    const activeTab = req.body?.active_tab || getTabFromReferer(req);
    const params = new URLSearchParams({ [status]: '1' });
    if (activeTab) params.set('tab', activeTab);
    return `/admin/conteudo?${params.toString()}`;
}

const loginRateLimit = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Muitas tentativas de login. Tente novamente em alguns minutos.'
});
const publicFormRateLimit = createRateLimiter({
    windowMs: 10 * 60 * 1000,
    max: 30,
    message: 'Muitas solicitacoes. Tente novamente em alguns minutos.'
});

function googlePlacesApiKey() {
    return process.env.GOOGLE_PLACES_API_KEY || process.env.GOOGLE_MAPS_API_KEY || '';
}

function extractGooglePlaceId(value = '') {
    const input = value.trim();
    if (/^[A-Za-z0-9_-]{20,}$/.test(input) && !input.includes('/')) return input;
    try {
        const url = new URL(input);
        const queryId = url.searchParams.get('query_place_id') || url.searchParams.get('place_id');
        if (queryId) return queryId;
        return decodeURIComponent(url.pathname).match(/!1s([A-Za-z0-9_-]{20,})/)?.[1] || '';
    } catch (e) { return ''; }
}

function extractGoogleMapsSearch(value = '') {
    const input = value.trim();
    const normalized = /^google\.[^/]+\//i.test(input) ? `https://www.${input}` : input;
    try {
        const url = new URL(normalized);
        const match = url.pathname.match(/\/maps\/place\/([^/]+)/i);
        return match ? decodeURIComponent(match[1].replace(/\+/g, ' ')).trim() : input;
    } catch (e) {
        return input;
    }
}

function extractGoogleMapsCoordinates(value = '') {
    const match = String(value).match(/@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/);
    if (!match) return null;
    const latitude = Number(match[1]);
    const longitude = Number(match[2]);
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return null;
    return { latitude, longitude };
}

async function getPlaceDetails(input) {
    const apiKey = googlePlacesApiKey();
    if (!apiKey) throw new Error('Configure GOOGLE_PLACES_API_KEY no .env do servidor.');
    const normalizedInput = /^google\.[^/]+\//i.test(input.trim()) ? `https://www.${input.trim()}` : input.trim();
    let placeId = extractGooglePlaceId(normalizedInput);
    if (!placeId) {
        const textQuery = extractGoogleMapsSearch(normalizedInput);
        const coordinates = extractGoogleMapsCoordinates(normalizedInput);
        const searchBody = { textQuery, languageCode: 'pt-BR' };
        if (coordinates) {
            searchBody.locationBias = {
                circle: { center: coordinates, radius: 250 }
            };
        }
        const response = await fetch('https://places.googleapis.com/v1/places:searchText', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': apiKey, 'X-Goog-FieldMask': 'places.id' },
            body: JSON.stringify(searchBody)
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error?.message || 'Empresa não localizada no Google.');
        placeId = result.places?.[0]?.id;
    }
    if (!placeId) throw new Error('Cole o link do Google Maps, Place ID ou nome completo da empresa.');
    const response = await fetch(`https://places.googleapis.com/v1/places/${encodeURIComponent(placeId)}?languageCode=pt-BR`, {
        headers: { 'X-Goog-Api-Key': apiKey, 'X-Goog-FieldMask': 'id,displayName,formattedAddress,googleMapsUri,googleMapsLinks,rating,userRatingCount,reviews' }
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || 'Não foi possível conectar esta empresa.');
    return result;
}

async function savePlacesReviews(place) {
    const reviews = Array.isArray(place.reviews) ? place.reviews : [];
    const [deletedRows] = await pool.execute('SELECT review_id FROM google_reviews_deleted');
    const deletedReviewIds = new Set(deletedRows.map(row => row.review_id));
    let saved = 0;
    for (const review of reviews) {
        if (deletedReviewIds.has(review.name)) continue;
        const text = (review.text?.text || review.originalText?.text || '').trim();
        if (!text) continue;
        const author = review.authorAttribution || {};
        await pool.execute(`INSERT INTO google_reviews
            (review_id, author_name, profile_photo_url, rating, comment, review_url, review_time, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE
            author_name=VALUES(author_name), profile_photo_url=VALUES(profile_photo_url), rating=VALUES(rating),
            comment=VALUES(comment), review_url=VALUES(review_url), review_time=VALUES(review_time), updated_at=NOW()`, [
            review.name || `${place.id}-${author.displayName || 'review'}-${review.publishTime || saved}`,
            author.displayName || 'Cliente Google', author.photoUri || null, Number(review.rating || 0), text,
            review.googleMapsUri || place.googleMapsUri || null, review.publishTime ? new Date(review.publishTime) : null
        ]);
        saved++;
    }
    return { received: reviews.length, saved };
}

async function syncGoogleReviews() {
    const [rows] = await pool.execute('SELECT place_id FROM reviews_google_connection WHERE id = 1');
    if (!rows[0]?.place_id) throw new Error('Conecte sua empresa antes de sincronizar.');
    const place = await getPlaceDetails(rows[0].place_id);
    return savePlacesReviews(place);
}

// Configuração Upload Multer Centralizado
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(dir)){ fs.mkdirSync(dir, { recursive: true }); }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + ext);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 20 * 1024 * 1024, files: 50 },
    fileFilter: (req, file, cb) => {
        if (!ALLOWED_UPLOAD_MIMES.has(file.mimetype)) {
            return cb(new Error('Tipo de arquivo nao permitido.'));
        }
        cb(null, true);
    }
});

const cmsUpload = upload.fields([
    { name: 'hero_image_file', maxCount: 1 }, 
    { name: 'hero_image_tablet_file', maxCount: 1 }, 
    { name: 'hero_image_mobile_file', maxCount: 1 }, 
    { name: 'hero_carousel_desktop_0_file', maxCount: 1 },
    { name: 'hero_carousel_tablet_0_file', maxCount: 1 },
    { name: 'hero_carousel_mobile_0_file', maxCount: 1 },
    { name: 'hero_carousel_desktop_1_file', maxCount: 1 },
    { name: 'hero_carousel_tablet_1_file', maxCount: 1 },
    { name: 'hero_carousel_mobile_1_file', maxCount: 1 },
    { name: 'hero_carousel_desktop_2_file', maxCount: 1 },
    { name: 'hero_carousel_tablet_2_file', maxCount: 1 },
    { name: 'hero_carousel_mobile_2_file', maxCount: 1 },
    { name: 'hero_carousel_desktop_3_file', maxCount: 1 },
    { name: 'hero_carousel_tablet_3_file', maxCount: 1 },
    { name: 'hero_carousel_mobile_3_file', maxCount: 1 },
    { name: 'hero_carousel_desktop_4_file', maxCount: 1 },
    { name: 'hero_carousel_tablet_4_file', maxCount: 1 },
    { name: 'hero_carousel_mobile_4_file', maxCount: 1 },
    { name: 'about_image_file', maxCount: 1 },
    { name: 'about_hero_image_file', maxCount: 1 },
    { name: 'about_hero_image_tablet_file', maxCount: 1 },
    { name: 'about_hero_image_mobile_file', maxCount: 1 },
    { name: 'services_hero_image_file', maxCount: 1 },
    { name: 'services_hero_image_tablet_file', maxCount: 1 },
    { name: 'services_hero_image_mobile_file', maxCount: 1 },
    { name: 'blog_hero_image_file', maxCount: 1 },
    { name: 'blog_hero_image_tablet_file', maxCount: 1 },
    { name: 'blog_hero_image_mobile_file', maxCount: 1 },
    { name: 'contact_hero_image_file', maxCount: 1 },
    { name: 'contact_hero_image_tablet_file', maxCount: 1 },
    { name: 'contact_hero_image_mobile_file', maxCount: 1 },
    { name: 'privacy_hero_image_file', maxCount: 1 },
    { name: 'privacy_hero_image_tablet_file', maxCount: 1 },
    { name: 'privacy_hero_image_mobile_file', maxCount: 1 },
    { name: 'terms_hero_image_file', maxCount: 1 },
    { name: 'terms_hero_image_tablet_file', maxCount: 1 },
    { name: 'terms_hero_image_mobile_file', maxCount: 1 },
    { name: 'topbar_gif', maxCount: 1 },
    { name: 'about_story_image_file', maxCount: 1 },
    { name: 'logo_file', maxCount: 1 },
    { name: 'logo_white_file', maxCount: 1 },
    { name: 'favicon_file', maxCount: 1 },
    { name: 'seo_share_image_file', maxCount: 1 },
    { name: 'license_qr_code_file', maxCount: 1 },
    { name: 'license_pdf_file', maxCount: 1 },
    { name: 'admin_logo_file', maxCount: 1 },
    { name: 'admin_header_logo_file', maxCount: 1 },
    { name: 'login_logo_file', maxCount: 1 },
    { name: 'admin_tutorial_image_file', maxCount: 1 },
    { name: 'destaque_paralaxe_image_file', maxCount: 1 },
    { name: 'promotional_banner_0_file', maxCount: 1 },
    { name: 'promotional_banner_1_file', maxCount: 1 }
]);

function handleCmsUpload(req, res, next) {
    cmsUpload(req, res, (err) => {
        if (!err) return next();
        console.error('CMS UPLOAD ERROR:', err.message);
        const params = new URLSearchParams({ error: '1', message: err.message });
        const activeTab = getTabFromReferer(req);
        if (activeTab) params.set('tab', activeTab);
        return res.redirect(`/admin/conteudo?${params.toString()}`);
    });
}

// Automação de Migração de Schema (Garantindo novos campos)
async function setupDB() {
    try {
        // Garantir Tabela de Configurações e Registro Raiz
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS configuracoes_globais (
                id INT PRIMARY KEY AUTO_INCREMENT,
                site_name VARCHAR(100) DEFAULT 'Sua Empresa'
            )
        `);
        const [rows] = await pool.execute('SELECT id FROM configuracoes_globais WHERE id = 1');
        if (rows.length === 0) {
            await pool.execute('INSERT INTO configuracoes_globais (id) VALUES (1)');
        }

        const columns = [
            'smtp_host VARCHAR(255)', 'smtp_port INT', 'smtp_user VARCHAR(255)', 'smtp_pass VARCHAR(255)',
            'meta_keywords TEXT', 'pinterest_pixel TEXT', 'linkedin_pixel TEXT', 'custom_head_code TEXT', 'custom_body_code TEXT',
            'email_reply_contact TEXT', 'email_reply_newsletter TEXT', 'email_subject_contact VARCHAR(255)', 'email_subject_newsletter VARCHAR(255)',
            'site_name VARCHAR(100)', 'footer_text TEXT', 'privacy_policy_content LONGTEXT', 'terms_conditions_content LONGTEXT',
            'privacy_hero_title TEXT', 'privacy_hero_label TEXT', 'privacy_hero_image TEXT', 'privacy_hero_image_tablet TEXT', 'privacy_hero_image_mobile TEXT',
            'terms_hero_title TEXT', 'terms_hero_label TEXT', 'terms_hero_image TEXT', 'terms_hero_image_tablet TEXT', 'terms_hero_image_mobile TEXT',
            'home_hero_title TEXT', 'home_hero_description TEXT', 'services_hero_title TEXT',
            'instagram_url VARCHAR(255)', 'linkedin_url VARCHAR(255)', 'facebook_url VARCHAR(255)', 'nav_cta_text VARCHAR(100)', 'endereco TEXT', 'whatsapp VARCHAR(50)', 'whatsapp_message TEXT',
            'color_marinho VARCHAR(20) DEFAULT "#002D80"', 'color_topbar VARCHAR(20) DEFAULT "#002D80"', 'color_areia VARCHAR(20) DEFAULT "#F7F7F4"', 'color_vermelho VARCHAR(20) DEFAULT "#D62828"', 'color_hero_button VARCHAR(50)', 'color_texto VARCHAR(20) DEFAULT "#333333"',
            'color_header VARCHAR(20) DEFAULT "#FFFFFF"', 'color_footer VARCHAR(20) DEFAULT "#0A1128"',
            'color_header_text VARCHAR(20) DEFAULT "#FFFFFF"', 'color_footer_text VARCHAR(20) DEFAULT "#FFFFFF"',
            'hero_image VARCHAR(255)', 'hero_image_tablet TEXT', 'hero_image_mobile TEXT', 'about_title VARCHAR(255)', 'about_text TEXT', 'about_image VARCHAR(255)', 'benefits_title VARCHAR(255)', 'benefits_text TEXT',
            'about_story_text_left TEXT', 'about_story_text_right TEXT', 'about_mission TEXT', 'about_vision TEXT', 'about_values TEXT', 'about_team_title VARCHAR(255)', 'about_team_text TEXT',
            'about_hero_title VARCHAR(255)', 'about_hero_image VARCHAR(255)', 'about_hero_image_tablet TEXT', 'about_hero_image_mobile TEXT', 'services_hero_image VARCHAR(255)', 'services_hero_image_tablet TEXT', 'services_hero_image_mobile TEXT', 'blog_hero_title VARCHAR(255)', 'blog_hero_image VARCHAR(255)', 'blog_hero_image_tablet TEXT', 'blog_hero_image_mobile TEXT', 'contact_hero_title VARCHAR(255)', 'contact_hero_image VARCHAR(255)', 'contact_hero_image_tablet TEXT', 'contact_hero_image_mobile TEXT', 'cnpj VARCHAR(50)',
            'logo VARCHAR(255)', 'logo_white VARCHAR(255)', 'favicon VARCHAR(255)', 'show_topbar INT DEFAULT 1', 'footer_secure_link VARCHAR(255)', 'footer_short_text TEXT',
            'services_section_title VARCHAR(255)', 'services_section_text TEXT', 'blog_section_title VARCHAR(255)', 'blog_section_text TEXT', 'testimonial_section_title VARCHAR(255)', 'newsletter_section_title VARCHAR(255)', 'newsletter_section_text TEXT',
            'services_page_description TEXT', 'blog_page_newsletter_title VARCHAR(255)', 'blog_page_newsletter_text TEXT', 'contact_page_description TEXT',
            'site_menu TEXT', 'footer_menu_1 TEXT', 'footer_menu_2 TEXT',
            'home_hero_card_title VARCHAR(255)', 'home_hero_card_subtitle VARCHAR(255)', 'home_hero_button_text VARCHAR(100)', 'home_about_button_text VARCHAR(100)', 'home_services_button_text VARCHAR(100)',
            'about_story_image VARCHAR(255)', 'social_links TEXT', 'about_story_lead TEXT', 'about_guidelines_title VARCHAR(255)', 'about_guidelines_text TEXT',
            'benefits_items TEXT', 'benefits_template VARCHAR(50)', 'benefits_color VARCHAR(50)', 'benefits_card_title_color VARCHAR(50)', 'benefits_card_text_color VARCHAR(50)', 'benefits_card_bg VARCHAR(50)',
            'hero_overlay_color VARCHAR(50) DEFAULT "#0A1128"', 'hero_overlay_opacity DECIMAL(3,2) DEFAULT 0.40',
            'hero_title_offset_y INT DEFAULT 0', 'hero_button_offset_y INT DEFAULT 0',
            'hero_title_offset_y_desktop INT DEFAULT 0', 'hero_title_offset_y_tablet INT DEFAULT 0', 'hero_title_offset_y_mobile INT DEFAULT 0',
            'hero_button_offset_y_desktop INT DEFAULT 0', 'hero_button_offset_y_tablet INT DEFAULT 0', 'hero_button_offset_y_mobile INT DEFAULT 0',
            'contact_section_title VARCHAR(255)', 'contact_section_subtitle TEXT',
            'contact_phone VARCHAR(50)', 'contact_email VARCHAR(255)', 'address_full TEXT', 'contact_map_url TEXT',
            'contact_form_title VARCHAR(255)', 'contact_form_recipient VARCHAR(255)',
            'license_qr_code VARCHAR(255)', 'license_nf_data TEXT',
            'license_pdf VARCHAR(255)', 'license_auth_code VARCHAR(255)',
            'template_version VARCHAR(50) DEFAULT "1.0.0"',
            'admin_primary_color VARCHAR(20) DEFAULT "#0A1128"', 'admin_accent_color VARCHAR(20) DEFAULT "#D62828"', 
            'admin_logo VARCHAR(255)', 'admin_header_logo VARCHAR(255)',
            'login_bg_color VARCHAR(20) DEFAULT "#0A1128"', 'login_card_bg VARCHAR(20) DEFAULT "#FFFFFF"', 
            'login_btn_bg VARCHAR(20) DEFAULT "#0A1128"', 'login_btn_text VARCHAR(255) DEFAULT "ACESSAR GOVERNANÇA"',
            'login_label_email VARCHAR(255) DEFAULT "Credencial de Acesso"', 'login_label_password VARCHAR(255) DEFAULT "Assinatura de Segurança"',
            'login_title VARCHAR(255) DEFAULT "Sistema CMS"', 'login_logo VARCHAR(255)',
            'contact_form_fields TEXT', 'header_strip_text TEXT', 'beneficios_json TEXT',
            'benefits_icon_bg VARCHAR(50)', 'benefits_icon_color VARCHAR(50)', 'benefits_title_color VARCHAR(50)', 'benefits_text_color VARCHAR(50)',
            'meta_title_home VARCHAR(255)', 'meta_description_home TEXT', 'seo_share_image TEXT', 'facebook_pixel TEXT', 'google_analytics TEXT',
            'license_expiry_date VARCHAR(50)', 'license_stripe_url VARCHAR(512)', 'license_stripe_payment_code VARCHAR(255)',
            'font_title VARCHAR(100) DEFAULT "Playfair Display"', 'font_body VARCHAR(100) DEFAULT "Inter Tight"',
            'title_size_hero_desktop DECIMAL(4,2)', 'title_size_hero_tablet DECIMAL(4,2)', 'title_size_hero_mobile DECIMAL(4,2)',
            'title_size_page_desktop DECIMAL(4,2)', 'title_size_page_tablet DECIMAL(4,2)', 'title_size_page_mobile DECIMAL(4,2)',
            'title_size_section_desktop DECIMAL(4,2)', 'title_size_section_tablet DECIMAL(4,2)', 'title_size_section_mobile DECIMAL(4,2)',
            'title_size_card_desktop DECIMAL(4,2)', 'title_size_card_tablet DECIMAL(4,2)', 'title_size_card_mobile DECIMAL(4,2)',
            'color_about_bg VARCHAR(20) DEFAULT "#F7F7F4"', 'color_blog_bg VARCHAR(20) DEFAULT "#0A1128"',
            'color_offcanvas_bg VARCHAR(20) DEFAULT "#FFFFFF"', 'color_offcanvas_text VARCHAR(20) DEFAULT "#333333"',
            'color_blog_text VARCHAR(20) DEFAULT "#FFFFFF"', 'color_contact_bg VARCHAR(20) DEFAULT "#F7F7F4"',
            'admin_tutorial_video VARCHAR(500)', 'admin_tutorial_image VARCHAR(500)',
            'layout_secoes TEXT', 'estilo_secoes TEXT', 'hero_carousel_json TEXT', 'header_transparent INT DEFAULT 0',
            'topbar_gif VARCHAR(255)',
            'topbar_font_size DECIMAL(4,2) DEFAULT 0.75', 'topbar_icon_size DECIMAL(4,2) DEFAULT 0.85',
            'header_font_size DECIMAL(4,2) DEFAULT 0.90', 'header_icon_size DECIMAL(4,2) DEFAULT 1.10',
            'contact_extra_title VARCHAR(255) DEFAULT "Gostaria de falar com nosso time?"', 'contact_extra_text TEXT',
            'color_popup_bg VARCHAR(15) DEFAULT "#FFFFFF"', 'color_popup_text VARCHAR(15) DEFAULT "#333333"',
            'color_popup_title VARCHAR(15) DEFAULT "#0A1128"', 'popup_border_radius INT DEFAULT 30',
            'color_popup_btn VARCHAR(15) DEFAULT "#0A1128"', 'color_popup_btn_text VARCHAR(15) DEFAULT "#FFFFFF"',
            'popup_image_style VARCHAR(15) DEFAULT "rounded"', 'popup_font_style VARCHAR(15) DEFAULT "sans-serif"',
            'popup_layout_model VARCHAR(20) DEFAULT "split"',
            'destaque_paralaxe_title TEXT',
            'destaque_paralaxe_subtitle TEXT',
            'destaque_paralaxe_button_text VARCHAR(100)',
            'destaque_paralaxe_button_url TEXT',
            'destaque_paralaxe_image TEXT',
            'destaque_paralaxe_align VARCHAR(20) DEFAULT "centered"'
        ];
        // Campos editoriais grandes em VARCHAR contam integralmente para o limite
        // de 65 KB da linha do MariaDB. TEXT mantém esse conteúdo fora da linha.
        const compactColumnDefinition = (definition) => definition.replace(
            /VARCHAR\((\d+)\)/i,
            (match, size) => Number(size) >= 100 ? 'TEXT' : match
        );

        for (const col of columns) {
            const safeCol = compactColumnDefinition(col);
            try {
                await pool.execute(`ALTER TABLE configuracoes_globais ADD COLUMN ${safeCol}`);
                console.log(`✅ DATABASE: Coluna [${col.split(' ')[0]}] provisionada.`);
            } catch (e) { 
                if (e.code === 'ER_DUP_COLUMN_NAMES' || e.errno === 1060) {
                    if (safeCol !== col) {
                        try {
                            await pool.execute(`ALTER TABLE configuracoes_globais MODIFY COLUMN ${safeCol}`);
                        } catch (compactError) {
                            console.error(`DATABASE: Erro ao compactar coluna [${col.split(' ')[0]}]:`, compactError.message);
                        }
                    }
                } else {
                    console.error(`❌ DATABASE: Erro ao provisionar coluna [${col.split(' ')[0]}]:`, e.message);
                }
            }
        }
        console.log('✅ DATABASE: Estrutura de Configurações Sincronizada.');

        await pool.execute(`
            CREATE TABLE IF NOT EXISTS configuracoes_visuais (
                id TINYINT PRIMARY KEY DEFAULT 1,
                hamburger_color VARCHAR(20) DEFAULT '#FFFFFF',
                social_icon_size DECIMAL(4,2) DEFAULT 1.25
            )
        `);
        await pool.execute('INSERT IGNORE INTO configuracoes_visuais (id) VALUES (1)');

        // Tabelas de Comentários e Depoimentos
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS comentarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                post_id VARCHAR(255),
                nome VARCHAR(100),
                email VARCHAR(100),
                comentario TEXT,
                aprovado BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS depoimentos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(100),
                cargo VARCHAR(100),
                empresa VARCHAR(100),
                texto TEXT,
                foto VARCHAR(255),
                aprovado BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS google_reviews (
                id INT AUTO_INCREMENT PRIMARY KEY,
                review_id VARCHAR(255) UNIQUE NOT NULL,
                author_name VARCHAR(255),
                profile_photo_url VARCHAR(512),
                rating INT DEFAULT 5,
                comment TEXT,
                review_url VARCHAR(512),
                review_time DATETIME NULL,
                ativo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS google_reviews_deleted (
                review_id VARCHAR(255) PRIMARY KEY,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.execute(`CREATE TABLE IF NOT EXISTS reviews_google_connection (
            id INT PRIMARY KEY DEFAULT 1, place_id VARCHAR(255) NOT NULL, business_name VARCHAR(255),
            business_address TEXT, google_url TEXT, write_review_url TEXT, rating DECIMAL(3,2),
            review_count INT DEFAULT 0, connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )`);
        await pool.execute(`CREATE TABLE IF NOT EXISTS reviews_widget_settings (
            id INT PRIMARY KEY DEFAULT 1, reviews_widget_layout VARCHAR(20) DEFAULT 'slider',
            reviews_widget_theme VARCHAR(20) DEFAULT 'light', reviews_widget_min_rating INT DEFAULT 4,
            reviews_widget_limit INT DEFAULT 8, reviews_widget_show_photos INT DEFAULT 1,
            reviews_widget_show_date INT DEFAULT 1, reviews_widget_autoplay INT DEFAULT 1,
            reviews_widget_bg VARCHAR(20) DEFAULT '#FFFFFF', reviews_widget_card_bg VARCHAR(20) DEFAULT '#F7F7F4',
            reviews_widget_accent VARCHAR(20) DEFAULT '#F59E0B'
        )`);
        await pool.execute('INSERT IGNORE INTO reviews_widget_settings (id) VALUES (1)');
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS equipe (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(255) NOT NULL,
                funcao VARCHAR(255) NOT NULL,
                imagem VARCHAR(255),
                ordem INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS posts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                slug VARCHAR(255) UNIQUE,
                titulo VARCHAR(255),
                categoria VARCHAR(100),
                data VARCHAR(100),
                resumo TEXT,
                imagem VARCHAR(255),
                conteudo LONGTEXT,
                meta_title VARCHAR(255),
                meta_description TEXT,
                destaque_home BOOLEAN DEFAULT FALSE,
                ordem INT DEFAULT 0,
                ativo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS servicos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                slug VARCHAR(255) UNIQUE,
                titulo VARCHAR(255),
                resumo TEXT,
                imagem VARCHAR(255),
                conteudo LONGTEXT,
                icone VARCHAR(100),
                meta_title VARCHAR(255),
                meta_description TEXT,
                destaque_home BOOLEAN DEFAULT FALSE,
                ordem INT DEFAULT 0,
                ativo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        for (const productColumn of [
            'preco_de DECIMAL(10,2) NULL',
            'preco_por DECIMAL(10,2) NULL',
            'unidade VARCHAR(50) NULL',
            'selo VARCHAR(100) NULL'
        ]) {
            try {
                await pool.execute(`ALTER TABLE servicos ADD COLUMN ${productColumn}`);
            } catch (e) {
                if (e.code !== 'ER_DUP_COLUMN_NAMES' && e.errno !== 1060) throw e;
            }
        }
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS banners (
                id INT AUTO_INCREMENT PRIMARY KEY,
                titulo VARCHAR(255),
                imagem VARCHAR(255) NOT NULL,
                link VARCHAR(500),
                texto_botao VARCHAR(100),
                ordem INT DEFAULT 0,
                ativo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        try {
            await pool.execute('ALTER TABLE banners ADD COLUMN posicao VARCHAR(30) DEFAULT "topo"');
        } catch (e) {
            if (e.code !== 'ER_DUP_COLUMN_NAMES' && e.errno !== 1060) throw e;
        }
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS beneficios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                icone VARCHAR(100) DEFAULT 'ri-checkbox-circle-line',
                titulo VARCHAR(255),
                texto TEXT,
                ordem INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS newsletter (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                status ENUM('ativo', 'cancelado') DEFAULT 'ativo',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        try {
            await pool.execute('ALTER TABLE newsletter ADD COLUMN nome VARCHAR(100) AFTER id');
            console.log('✅ DATABASE: Coluna [nome] adicionada à Newsletter.');
        } catch (e) { /* Coluna já existe */ }

        console.log('✅ DATABASE: Postagens, Serviços e Newsletter (CMS) Prontos.');

        // Tabela de Diferenciais (Substituindo JSON para maior estabilidade)
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS diferenciais (
                id INT AUTO_INCREMENT PRIMARY KEY,
                titulo VARCHAR(255),
                texto TEXT,
                icone VARCHAR(100),
                ordem INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Migração Opcional: Se a tabela diferenciais estiver vazia e houver dados no JSON antigo
        const [difExists] = await pool.execute('SELECT id FROM diferenciais LIMIT 1');
        if (difExists.length === 0) {
            const [rows] = await pool.execute('SELECT benefits_items FROM configuracoes_globais WHERE id = 1');
            if (rows[0] && rows[0].benefits_items) {
                try {
                    const items = JSON.parse(rows[0].benefits_items);
                    for (const item of items) {
                        if (item.title || item.text) {
                            await pool.execute('INSERT INTO diferenciais (titulo, texto, icone) VALUES (?, ?, ?)', 
                                [item.title, item.text, item.icon || 'ri-star-line']);
                        }
                    }
                    console.log('✅ DATABASE: Migração de Diferenciais concluída.');
                } catch(e) { console.error('⚠️ Erro na migração de diferenciais:', e.message); }
            }
        }

        // Inserir Dados Iniciais se estiver vazio
        const [postsExist] = await pool.execute('SELECT id FROM posts LIMIT 1');
        if (postsExist.length === 0) {
            await pool.execute('INSERT INTO posts (slug, titulo, categoria, data, resumo, imagem, conteudo) VALUES ("confianca-capital-psicologico", "Confiança e Capital Psicológico", "Liderança", "05 Abr 2024", "Como a confiança nas organizações impulsiona a inovação e o crescimento.", "https://images.unsplash.com/photo-1552664730-d307ca884978?auto=format&fit=crop&q=80&w=800", "<h3>Confiança: A Base da Eficiência</h3><p>Construir um ambiente seguro é o primeiro passo para o sucesso.</p>")');
            console.log('✅ DATABASE: Posts Iniciais Migrados.');
        }

        console.log('✅ DATABASE: Portfólio de Especialidades gerenciado pelo painel.');

        await pool.execute(`
            CREATE TABLE IF NOT EXISTS filiais (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(100) NOT NULL,
                cidade VARCHAR(100) NOT NULL,
                estado VARCHAR(2) NOT NULL,
                bairros TEXT,
                link VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ DATABASE: Tabela de Filiais Pronta.');

        // Garantir Usuário Admin Padrão
        // Tabela de Usuários (Login Admin) com Nível de Acesso e Permissões
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                senha VARCHAR(255) NOT NULL,
                nivel ENUM('superadmin', 'admin', 'editor') DEFAULT 'admin',
                permissoes TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Garantir Coluna Nível e ENUM estendido (superadmin) e Coluna Permissões
        try { 
            await pool.execute("ALTER TABLE usuarios MODIFY COLUMN nivel ENUM('superadmin', 'admin', 'editor') DEFAULT 'admin'");
        } catch(e) {
            try { await pool.execute("ALTER TABLE usuarios ADD COLUMN nivel ENUM('superadmin', 'admin', 'editor') DEFAULT 'admin'"); } catch(err) {}
        }
        try {
            await pool.execute("ALTER TABLE usuarios ADD COLUMN permissoes TEXT NULL");
        } catch(e) {}

        // Garantir que SuperAdmin e Admin existam sem sobrescrever senhas alteradas
        const [existingUsers] = await pool.execute('SELECT email FROM usuarios');
        const userEmails = existingUsers.map(u => u.email);

        if (!userEmails.includes('superadmin@etodavia.com')) {
            const hashedSuper = await bcrypt.hash('ET.2026*', 10);
            await pool.execute('INSERT INTO usuarios (nome, email, senha, nivel) VALUES (?, ?, ?, ?)', 
                ['Super Admin ET', 'superadmin@etodavia.com', hashedSuper, 'superadmin']);
        }

        if (!userEmails.includes('admin@agenciaetodavia.com.br')) {
            const hashedAdmin = await bcrypt.hash('123654*', 10);
            await pool.execute('INSERT INTO usuarios (nome, email, senha, nivel) VALUES (?, ?, ?, ?)', 
                ['Vcadmin', 'admin@agenciaetodavia.com.br', hashedAdmin, 'admin']);
        }

        console.log('✅ DATABASE: Usuários (Super/Admin) sincronizados/atualizados.');
    } catch (err) { console.error('❌ DATABASE: Falha na sincronização.', err); }
}
setupDB();

const app = express();

// Security and Parsers
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.locals.assetVersion = ASSET_VERSION;

// EJS Config
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.get('/img/hero_optimo.png', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.sendFile(path.join(__dirname, 'public', 'img', 'hero_optimo.png'));
});
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads'), {
    maxAge: '365d',
    immutable: true,
    etag: true,
    lastModified: true,
    setHeaders: (res) => {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
}));
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '365d',
    immutable: true,
    etag: true,
    lastModified: true,
    setHeaders: (res) => {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
}));
app.get('/img/placeholder-user.png', (req, res) => res.redirect(301, '/img/placeholder-user.svg'));
app.get('/img/placeholder-post.png', (req, res) => res.redirect(301, '/img/placeholder-post.svg'));

// MIDDLEWARE DE GOVERNANÇA DE NAVEGAÇÃO (ESTADO ATIVO DOS MENUS)
app.use((req, res, next) => {
    const path = req.path;
    if (path === '/') res.locals.currentPage = 'home';
    else if (path.startsWith('/blog')) res.locals.currentPage = 'blog';
    else if (path.startsWith('/politica')) res.locals.currentPage = 'politica';
    else if (path.startsWith('/termos')) res.locals.currentPage = 'termos';
    else res.locals.currentPage = '';
    next();
});

// Middleware de Governança de Acesso (RBAC Industrial via JWT Cookie)
app.use((req, res, next) => {
    let role = null;
    let isAuthenticated = false;
    let perms = [];
    let userObj = null;
    try {
        const cookies = parseCookies(req.headers.cookie || '');
        const token = cookies.token;
        if (token) {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            role = decoded.user.nivel || 'admin';
            req.user = decoded.user;
            perms = decoded.user.permissoes || [];
            userObj = decoded.user;
            isAuthenticated = true;
        }
    } catch (err) {
        role = null;
        isAuthenticated = false;
        perms = [];
        userObj = null;
    }
    
    res.locals.userRole = role;
    res.locals.isAuthenticated = isAuthenticated;
    res.locals.userPermissions = perms;
    res.locals.user = userObj;
    res.locals.assetVersion = ASSET_VERSION;

    // Bloqueio rígido para qualquer rota administrativa (/admin) exceto login
    if (req.path.startsWith('/admin') && req.path !== '/admin/login') {
        if (!isAuthenticated) {
            return res.redirect('/admin/login');
        }

        // Restrição de rotas baseada em permissão se não for superadmin
        if (role !== 'superadmin') {
            // Proibir acesso a rotas de gestão de usuários
            if (req.path.startsWith('/admin/usuarios')) {
                return res.redirect('/admin/dashboard?error=1&message=Acesso+negado');
            }
            
            // Verificar permissões específicas
            if (req.path.startsWith('/admin/depoimentos') && !perms.includes('depoimentos')) {
                return res.redirect('/admin/dashboard?error=1&message=Acesso+negado');
            }
            if (req.path.startsWith('/admin/config') && !perms.includes('config')) {
                return res.redirect('/admin/dashboard?error=1&message=Acesso+negado');
            }
            if (req.path.startsWith('/admin/conteudo') && !perms.includes('cms')) {
                return res.redirect('/admin/dashboard?error=1&message=Acesso+negado');
            }
            if (req.path.startsWith('/admin/servicos') && !perms.includes('servicos')) {
                return res.redirect('/admin/dashboard?error=1&message=Acesso+negado');
            }
        }
    }

    // Se já estiver logado, não há necessidade de ver a tela de login novamente
    if (req.path === '/admin/login' && isAuthenticated) {
        return res.redirect('/admin/dashboard');
    }

    next();
});

// Middleware Global para Configurações (Acessível em todas as Views)
app.use(async (req, res, next) => {
    if (req.path.startsWith('/admin') || req.path.startsWith('/api') || req.path === '/colher-depoimento' || req.path === '/depoimentos/novo') {
        res.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
    }

    try {
        const [rows] = await pool.execute('SELECT * FROM configuracoes_globais WHERE id = 1 LIMIT 1');
        let visualSettings = {};
        try {
            const [visualRows] = await pool.execute('SELECT * FROM configuracoes_visuais WHERE id = 1 LIMIT 1');
            visualSettings = visualRows[0] || {};
        } catch (visualError) {}
        const settings = { whatsapp: '5511999999999', cnpj: '00.000.000/0001-00', ...(rows[0] || {}), ...visualSettings };
        
        // Verificação de Status da Licença (Carência de 30 dias / Expirada)
        let licenseStatus = 'active'; // active, grace, expired
        let daysOverdue = 0;
        
        if (settings.license_expiry_date) {
            const expiryDate = new Date(settings.license_expiry_date);
            const currentDate = new Date();
            
            // Zerar as horas para comparação correta de datas
            expiryDate.setHours(0, 0, 0, 0);
            currentDate.setHours(0, 0, 0, 0);
            
            if (currentDate > expiryDate) {
                const diffTime = Math.abs(currentDate - expiryDate);
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
                daysOverdue = diffDays;
                
                if (diffDays <= 30) {
                    licenseStatus = 'grace'; // Período de carência (1 a 30 dias de atraso)
                } else {
                    licenseStatus = 'expired'; // Suspenso (mais de 30 dias de atraso)
                }
            }
        }
        
        const forwardedProto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
        const protocol = forwardedProto || req.protocol || 'http';
        const host = req.get('host');
        res.locals.baseUrl = `${protocol}://${host}`;
        res.locals.currentUrl = `${res.locals.baseUrl}${req.originalUrl}`;
        const canonicalPath = req.path === '/' ? '/' : req.path.replace(/\/$/, '');
        res.locals.canonicalUrl = `${res.locals.baseUrl}${canonicalPath}`;
        res.locals.isAdminPage = req.path.startsWith('/admin');
        res.locals.absoluteAssetUrl = (assetPath) => {
            if (!assetPath) return '';
            if (/^https?:\/\//i.test(assetPath)) return assetPath;
            return `${res.locals.baseUrl}${assetPath.startsWith('/') ? assetPath : '/' + assetPath}`;
        };
        res.locals.settings = settings;
        res.locals.licenseStatus = licenseStatus;
        res.locals.daysOverdue = daysOverdue;
        next();
    } catch (err) {
        const forwardedProto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
        const protocol = forwardedProto || req.protocol || 'http';
        const host = req.get('host');
        const canonicalPath = req.path === '/' ? '/' : req.path.replace(/\/$/, '');
        res.locals.baseUrl = `${protocol}://${host}`;
        res.locals.currentUrl = `${res.locals.baseUrl}${req.originalUrl}`;
        res.locals.canonicalUrl = `${res.locals.baseUrl}${canonicalPath}`;
        res.locals.isAdminPage = req.path.startsWith('/admin');
        res.locals.absoluteAssetUrl = (assetPath) => {
            if (!assetPath) return '';
            if (/^https?:\/\//i.test(assetPath)) return assetPath;
            return `${res.locals.baseUrl}${assetPath.startsWith('/') ? assetPath : '/' + assetPath}`;
        };
        res.locals.settings = { whatsapp: '5511999999999', cnpj: '00.000.000/0001-00' };
        res.locals.licenseStatus = 'active';
        res.locals.daysOverdue = 0;
        next();
    }
});

app.get('/robots.txt', (req, res) => {
    res.type('text/plain').send([
        'User-agent: *',
        'Allow: /',
        'Disallow: /admin/',
        'Disallow: /api/',
        `Sitemap: ${res.locals.baseUrl}/sitemap.xml`
    ].join('\n'));
});

app.get('/llms.txt', (req, res) => {
    const siteName = res.locals.settings?.site_name || 'Sua Empresa';
    const description = res.locals.settings?.meta_description_home || `${siteName} oferece serviços de mudanças, transporte e logística.`;
    res.type('text/plain').send([
        `# ${siteName}`,
        '',
        `> ${description}`,
        '',
        '## Páginas principais',
        `- [Início](${res.locals.baseUrl}/)`,
        `- [Blog](${res.locals.baseUrl}/blog)`,
        `- [Política de Privacidade](${res.locals.baseUrl}/politica-de-privacidade)`,
        `- [Termos e Condições](${res.locals.baseUrl}/termos-e-condicoes)`
    ].join('\n'));
});

app.get('/sitemap.xml', async (req, res) => {
    const urls = [
        { loc: '/', priority: '1.0', changefreq: 'weekly' },
        { loc: '/blog', priority: '0.7', changefreq: 'weekly' },
        { loc: '/politica-de-privacidade', priority: '0.3', changefreq: 'yearly' },
        { loc: '/termos-e-condicoes', priority: '0.3', changefreq: 'yearly' }
    ];

    try {
        const [posts] = await pool.execute('SELECT slug, created_at FROM posts WHERE ativo = 1 ORDER BY created_at DESC');
        posts.forEach((post) => urls.push({
            loc: `/blog/${encodeURIComponent(post.slug)}`,
            lastmod: post.created_at,
            priority: '0.6',
            changefreq: 'monthly'
        }));
    } catch (err) {
        console.warn('Sitemap gerado sem artigos:', err.message);
    }

    const escapeXml = (value) => String(value).replace(/[<>&'\"]/g, (char) => ({
        '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;'
    }[char]));
    const entries = urls.map((item) => {
        const lastmod = item.lastmod ? `<lastmod>${new Date(item.lastmod).toISOString().slice(0, 10)}</lastmod>` : '';
        return `<url><loc>${escapeXml(res.locals.baseUrl + item.loc)}</loc>${lastmod}<changefreq>${item.changefreq}</changefreq><priority>${item.priority}</priority></url>`;
    }).join('');

    res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${entries}</urlset>`);
});

// URLs antigas do template agora apontam para as seções equivalentes da landing page.
app.get('/sobre', (req, res) => res.redirect(301, '/#sobre'));
app.get('/servicos', (req, res) => res.redirect(301, '/#servicos'));
app.get('/servicos/:slug', (req, res) => res.redirect(301, '/#servicos'));
app.get('/contato', (req, res) => res.redirect(301, '/#contato'));

function renderNotFound(res) {
    const siteName = res.locals.settings?.site_name || 'Sua Empresa';
    res.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
    res.locals.isNotFoundPage = true;
    return res.status(404).render('404', {
        title: `Página não encontrada | ${siteName}`,
        description: `A página solicitada não foi encontrada no site da ${siteName}.`
    });
}

// FRONT-END ROUTES (DATABASE DRIVEN)
app.get('/', async (req, res) => {
    let posts = [];
    let services = [];
    let team = [];
    let testimonials = [];
    let beneficios = [];
    let banners = [];
    let promotionalBanners = [];
    let testimonialSource = 'manual';

    try {
        try {
            const [widgetRows] = await pool.execute('SELECT * FROM reviews_widget_settings WHERE id = 1');
            Object.assign(res.locals.settings, widgetRows[0] || {});
        } catch (err) {}
        // Consultar Benefícios
        [beneficios] = await pool.execute('SELECT * FROM beneficios ORDER BY ordem ASC, created_at ASC');
        [banners] = await pool.execute('SELECT * FROM banners WHERE ativo = 1 AND (posicao = "topo" OR posicao IS NULL) ORDER BY ordem ASC, created_at DESC');
        [promotionalBanners] = await pool.execute('SELECT * FROM banners WHERE ativo = 1 AND posicao = "promocional" ORDER BY ordem ASC, created_at DESC');

        // Consultar Posts (com fallback)
        try {
            [posts] = await pool.execute('SELECT * FROM posts WHERE destaque_home = 1 AND ativo = 1 ORDER BY ordem ASC, created_at DESC LIMIT 4');
            if (posts.length === 0) [posts] = await pool.execute('SELECT * FROM posts WHERE ativo = 1 ORDER BY created_at DESC LIMIT 4');
        } catch (err) {
            console.warn('⚠️ Fallback Post Query (Missing Columns?):', err.message);
            [posts] = await pool.execute('SELECT * FROM posts ORDER BY created_at DESC LIMIT 4');
        }

        // Consultar Serviços (com fallback)
        try {
            [services] = await pool.execute('SELECT * FROM servicos WHERE ativo = 1 ORDER BY ordem ASC, titulo ASC');
        } catch (err) {
            console.warn('⚠️ Fallback Service Query (Missing Columns?):', err.message);
            [services] = await pool.execute('SELECT * FROM servicos ORDER BY titulo ASC');
        }

        // Consultar Equipe e Depoimentos
        [team] = await pool.execute('SELECT * FROM equipe ORDER BY ordem ASC, created_at DESC');

        let filiais = [];
        try {
            [filiais] = await pool.execute('SELECT * FROM filiais ORDER BY nome ASC');
        } catch (err) {}
        
        try {
            const widgetMinRating = Math.min(5, Math.max(1, parseInt(res.locals.settings?.reviews_widget_min_rating, 10) || 4));
            const widgetLimit = Math.min(20, Math.max(1, parseInt(res.locals.settings?.reviews_widget_limit, 10) || 8));
            const [googleReviews] = await pool.execute(`
                SELECT
                    id,
                    author_name AS nome,
                    '' AS cargo,
                    'Google Meu Negocio' AS empresa,
                    comment AS texto,
                    profile_photo_url AS foto,
                    rating,
                    review_url,
                    review_time,
                    'google' AS origem
                FROM google_reviews
                WHERE ativo = TRUE AND rating >= ?
                ORDER BY review_time DESC, updated_at DESC
                LIMIT ${widgetLimit}
            `, [widgetMinRating]);
            if (googleReviews.length > 0) {
                testimonials = googleReviews;
                testimonialSource = 'google';
            } else {
                [testimonials] = await pool.execute('SELECT *, NULL AS rating, NULL AS review_url, "manual" AS origem FROM depoimentos WHERE aprovado = TRUE ORDER BY created_at DESC');
            }
        } catch (err) {
            [testimonials] = await pool.execute('SELECT *, NULL AS rating, NULL AS review_url, "manual" AS origem FROM depoimentos ORDER BY created_at DESC');
        }
        
        res.render('index', { 
            title: res.locals.settings?.meta_title_home || `${res.locals.settings?.site_name || 'Sua Empresa'} | Mudanças e Logística`,
            description: res.locals.settings?.meta_description_home || `${res.locals.settings?.site_name || 'Sua Empresa'}: soluções de mudanças e logística com atendimento personalizado. Solicite um orçamento.`,
            keywords: res.locals.settings?.meta_keywords || 'mudanças, transportes, logística, empresa de mudanças, orçamento de mudança',
            posts,
            services,
            team,
            testimonials,
            testimonialSource,
            beneficios,
            banners,
            promotionalBanners,
            filiais
        });
    } catch (e) { 
        console.error('❌ CRITICAL HOME ROUTE ERROR:', e);
        const siteName = res.locals.settings?.site_name || 'Sua Empresa';
        res.render('index', {
            title: res.locals.settings?.meta_title_home || `${siteName} | Mudanças e Logística`,
            description: res.locals.settings?.meta_description_home || `Conheça os produtos e serviços da ${siteName}.`,
            keywords: res.locals.settings?.meta_keywords || '',
            posts: [], services: [], team: [], testimonials: [], testimonialSource: 'manual', beneficios: [], banners: [], promotionalBanners: []
        });
    }
});

/* Public pages removed: sobre, servicos and service detail.
   These routes are intentionally disabled for the Logistica project.
app.get('/sobre', async (req, res) => {
    try {
        const [team] = await pool.execute('SELECT * FROM equipe ORDER BY ordem ASC, created_at DESC');
        res.render('sobre', { title: 'Sobre | Sua Empresa', team });
    } catch (e) { res.render('sobre', { title: 'Sobre | Sua Empresa', team: [] }); }
});

app.get('/servicos', async (req, res) => {
    try {
        const [services] = await pool.execute('SELECT * FROM servicos WHERE ativo = 1 ORDER BY ordem ASC, titulo ASC');
        res.render('servicos', { title: 'Serviços | Sua Empresa', services });
    } catch (e) { res.render('servicos', { title: 'Serviços | Sua Empresa', services: [] }); }
});

app.get('/servicos/:slug', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM servicos WHERE slug = ? AND ativo = 1', [req.params.slug]);
        const service = rows[0];
        if (!service) return res.redirect('/servicos');
        const [comments] = await pool.execute('SELECT * FROM comentarios WHERE post_id = ? AND aprovado = TRUE', [req.params.slug]);
        res.render('service-detail', { 
            title: service.meta_title || `${service.titulo} | Sua Empresa`, 
            description: service.meta_description || service.resumo,
            service, 
            comments 
        });
    } catch (e) { res.redirect('/servicos'); }
});
*/

// ROTA PÚBLICA PARA COLETAR DEPOIMENTOS
app.get('/colher-depoimento', (req, res) => {
    res.render('public-form-depoimento', { title: 'Compartilhe sua Experiência' });
});

app.post('/api/public-depoimento', upload.single('foto_file'), async (req, res) => {
    const { nome, cargo, empresa, texto } = req.body;
    let foto = null;
    if (req.file) foto = `/uploads/${req.file.filename}`;
    
    try {
        await pool.execute(
            'INSERT INTO depoimentos (nome, cargo, empresa, texto, foto, aprovado) VALUES (?, ?, ?, ?, ?, ?)',
            [nome, cargo, empresa, texto, foto, 0] // 0 = Pendente
        );
        res.status(200).json({ success: true });
    } catch (err) {
        console.error('❌ PUBLIC TESTIMONIAL ERROR:', err);
        res.status(500).json({ error: 'Erro ao salvar depoimento' });
    }
});

app.get('/blog', async (req, res) => {
    const siteName = res.locals.settings?.site_name || 'Sua Empresa';
    const blogDescription = `Conteúdos e dicas da ${siteName} sobre mudanças, transporte e logística.`;
    try {
        const [posts] = await pool.execute('SELECT * FROM posts WHERE ativo = 1 ORDER BY created_at DESC');
        res.render('blog', { title: `Blog | ${siteName}`, description: blogDescription, posts });
    } catch (e) {
        res.render('blog', { title: `Blog | ${siteName}`, description: blogDescription, posts: [] });
    }
});

app.get('/blog/:slug', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM posts WHERE slug = ?', [req.params.slug]);
        const post = rows[0];
        if (!post) return renderNotFound(res);
        const [comments] = await pool.execute('SELECT * FROM comentarios WHERE post_id = ? AND aprovado = TRUE ORDER BY created_at DESC', [req.params.slug]);
        res.render('post', { 
            title: post.meta_title || `${post.titulo} | ${res.locals.settings?.site_name || 'Sua Empresa'}`,
            description: post.meta_description || post.resumo,
            article: post,
            post, 
            comments,
            success: req.query.success,
            error: req.query.error
        });
    } catch (e) { res.redirect('/blog'); }
});

// Rota de ativação manual de licença
app.post('/api/licenca/ativar', requireApiAuth, async (req, res) => {
    const { code } = req.body;
    if (!code) {
        return res.status(400).json({ success: false, error: 'Código de ativação é obrigatório.' });
    }

    try {
        const [rows] = await pool.execute('SELECT license_stripe_payment_code FROM configuracoes_globais WHERE id = 1');
        const settings = rows[0] || {};
        
        if (code.trim() === (settings.license_stripe_payment_code || '').trim()) {
            // Estender licença por 1 ano (365 dias) a partir de hoje
            const nextYear = new Date();
            nextYear.setFullYear(nextYear.getFullYear() + 1);
            const expiryDateStr = nextYear.toISOString().split('T')[0];

            await pool.execute('UPDATE configuracoes_globais SET license_expiry_date = ? WHERE id = 1', [expiryDateStr]);
            return res.json({ success: true, expiryDate: expiryDateStr });
        } else {
            return res.status(400).json({ success: false, error: 'Código de pagamento Stripe inválido. Verifique o código e tente novamente.' });
        }
    } catch (e) {
        console.error('Erro ao ativar licença:', e);
        return res.status(500).json({ success: false, error: 'Erro interno ao processar ativação.' });
    }
});

// CMS ADMIN ROUTES
app.get('/admin/conteudo', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM configuracoes_globais WHERE id = 1');
        let visualSettings = {};
        try {
            const [visualRows] = await pool.execute('SELECT * FROM configuracoes_visuais WHERE id = 1');
            visualSettings = visualRows[0] || {};
        } catch (visualError) {}
        const settings = { ...(rows[0] || {}), ...visualSettings };
        const [beneficios] = await pool.execute('SELECT * FROM beneficios ORDER BY ordem ASC, created_at ASC');
        const [promotionalBanners] = await pool.execute('SELECT * FROM banners WHERE posicao = "promocional" ORDER BY ordem ASC, created_at ASC LIMIT 2');
        const [filiais] = await pool.execute('SELECT * FROM filiais ORDER BY nome ASC');
        
        res.render('admin/conteudo', { 
            title: 'Editor Global (CMS)', 
            success: req.query.success,
            error: req.query.error,
            errorMessage: req.query.message,
            activeTab: req.query.tab || '',
            settings,
            beneficios,
            promotionalBanners,
            filiais
        });
    } catch (e) {
        console.error('❌ CMS GET ERROR:', e);
        res.render('admin/conteudo', { title: 'Editor Global (CMS)', settings: {}, beneficios: [], promotionalBanners: [], filiais: [] });
    }
});
app.post('/admin/conteudo', handleCmsUpload, async (req, res) => {
    let updateData = { ...req.body };
    const files = req.files || {};
    if (files['logo_file']) updateData.logo = `/uploads/${files['logo_file'][0].filename}`;
    if (files['logo_white_file']) updateData.logo_white = `/uploads/${files['logo_white_file'][0].filename}`;
    if (files['favicon_file']) updateData.favicon = `/uploads/${files['favicon_file'][0].filename}`;
    if (files['about_story_image_file']) updateData.about_story_image = `/uploads/${files['about_story_image_file'][0].filename}`;
    if (files['topbar_gif']) updateData.topbar_gif = `/uploads/${files['topbar_gif'][0].filename}`;
    if (files['hero_image_file']) updateData.hero_image = `/uploads/${files['hero_image_file'][0].filename}`;
    
    // Whitelist de colunas válidas no banco para evitar erros de SQL
    const validColumns = [
        'site_name', 'footer_text', 'privacy_policy_content', 'terms_conditions_content',
        'privacy_hero_title', 'privacy_hero_label', 'privacy_hero_image', 'privacy_hero_image_tablet', 'privacy_hero_image_mobile',
        'terms_hero_title', 'terms_hero_label', 'terms_hero_image', 'terms_hero_image_tablet', 'terms_hero_image_mobile',
        'home_hero_title', 'home_hero_description', 'services_hero_title',
        'instagram_url', 'linkedin_url', 'facebook_url', 'nav_cta_text', 'endereco', 'whatsapp', 'whatsapp_message',
        'color_marinho', 'color_topbar', 'color_areia', 'color_vermelho', 'color_texto', 'color_header', 'color_footer',
        'color_header_text', 'color_footer_text', 'hero_image', 'hero_image_tablet', 'hero_image_mobile', 'about_title', 'about_text', 'about_image',
        'about_story_text_left', 'about_story_text_right',
        'about_mission', 'about_vision', 'about_values', 'about_team_title', 'about_team_text',
        'about_hero_title', 'about_hero_image', 'about_hero_image_tablet', 'about_hero_image_mobile',
        'services_hero_image', 'services_hero_image_tablet', 'services_hero_image_mobile',
        'blog_hero_title', 'blog_hero_image', 'blog_hero_image_tablet', 'blog_hero_image_mobile',
        'contact_hero_title', 'contact_hero_image', 'contact_hero_image_tablet', 'contact_hero_image_mobile', 'cnpj', 'logo', 'logo_white', 'favicon', 'show_topbar',
        'footer_secure_link', 'footer_short_text', 'services_section_title', 'services_section_text',
        'blog_section_title', 'blog_section_text', 'testimonial_section_title', 'newsletter_section_title',
        'newsletter_section_text', 'services_page_description', 'blog_page_newsletter_title',
        'blog_page_newsletter_text', 'contact_page_description', 'site_menu', 'footer_menu_1', 'footer_menu_2', 'home_hero_card_title',
        'home_hero_card_subtitle', 'home_hero_button_text', 'home_about_button_text', 'home_services_button_text', 'about_story_image',
        'about_story_lead', 'about_guidelines_title', 'about_guidelines_text',
        'social_links', 'benefits_title', 'benefits_text', 'beneficios_json', 
        'hero_overlay_color',
        'hero_overlay_opacity', 'hero_title_offset_y', 'hero_button_offset_y',
        'hero_title_offset_y_desktop', 'hero_title_offset_y_tablet', 'hero_title_offset_y_mobile',
        'hero_button_offset_y_desktop', 'hero_button_offset_y_tablet', 'hero_button_offset_y_mobile',
        'contact_section_title', 'contact_section_subtitle', 'contact_phone', 'contact_email', 'address_full', 'contact_map_url',
        'contact_form_title', 'contact_form_recipient', 'license_qr_code', 'license_nf_data',
        'license_pdf', 'license_auth_code', 'admin_primary_color', 'admin_accent_color', 'admin_logo', 'admin_header_logo', 'contact_form_fields',
        'login_bg_color', 'login_card_bg', 'login_btn_bg', 'login_btn_text', 'login_label_email', 'login_label_password', 'login_title', 'login_logo',
        'header_strip_text', 'meta_title_home', 'meta_description_home', 'seo_share_image', 'meta_keywords', 'facebook_pixel', 'google_analytics', 'pinterest_pixel', 'linkedin_pixel', 'custom_head_code', 'custom_body_code',
        'license_expiry_date', 'license_stripe_url', 'license_stripe_payment_code', 'template_version',
        'font_title', 'font_body',
        'title_size_hero_desktop', 'title_size_hero_tablet', 'title_size_hero_mobile',
        'title_size_page_desktop', 'title_size_page_tablet', 'title_size_page_mobile',
        'title_size_section_desktop', 'title_size_section_tablet', 'title_size_section_mobile',
        'title_size_card_desktop', 'title_size_card_tablet', 'title_size_card_mobile',
        'color_hero_button', 'color_about_bg', 'color_blog_bg', 'color_blog_text', 'color_contact_bg',
        'color_offcanvas_bg', 'color_offcanvas_text',
        'benefits_color', 'benefits_text_color', 'benefits_title_color', 'benefits_icon_bg', 'benefits_icon_color', 'benefits_card_title_color', 'benefits_card_text_color', 'benefits_card_bg',
        'admin_tutorial_video', 'admin_tutorial_image',
        'layout_secoes', 'estilo_secoes', 'hero_carousel_json', 'header_transparent',
        'topbar_gif',
        'topbar_font_size', 'topbar_icon_size', 'header_font_size', 'header_icon_size',
        'contact_extra_title', 'contact_extra_text',
        'color_popup_bg', 'color_popup_text', 'color_popup_title', 'popup_border_radius',
        'color_popup_btn', 'color_popup_btn_text', 'popup_image_style', 'popup_font_style', 'popup_layout_model',
        'destaque_paralaxe_title', 'destaque_paralaxe_subtitle', 'destaque_paralaxe_button_text', 'destaque_paralaxe_button_url', 'destaque_paralaxe_align', 'destaque_paralaxe_image'
    ];

    // Processar Uploads
    const fileFields = [
        'hero_image', 'hero_image_tablet', 'hero_image_mobile', 'about_image',
        'about_hero_image', 'about_hero_image_tablet', 'about_hero_image_mobile', 
        'services_hero_image', 'services_hero_image_tablet', 'services_hero_image_mobile',
        'blog_hero_image', 'blog_hero_image_tablet', 'blog_hero_image_mobile',
        'contact_hero_image', 'contact_hero_image_tablet', 'contact_hero_image_mobile',
        'privacy_hero_image', 'privacy_hero_image_tablet', 'privacy_hero_image_mobile',
        'terms_hero_image', 'terms_hero_image_tablet', 'terms_hero_image_mobile',
        'about_story_image', 'logo', 'logo_white', 'favicon', 'seo_share_image',
        'license_qr_code', 'license_pdf', 'admin_logo', 'admin_header_logo',
        'login_logo', 'admin_tutorial_image', 'destaque_paralaxe_image'
    ];

    fileFields.forEach(field => {
        const fileKey = field + '_file';
        const removeKey = field + '_remove';
        if (updateData[removeKey] === '1') {
            updateData[field] = '';
        }
        if(req.files && req.files[fileKey]) {
            updateData[field] = `/uploads/${req.files[fileKey][0].filename}`;
        } else if (typeof updateData[field] === 'string' && updateData[field].startsWith('/uploads/')) {
            const storedPath = path.join(__dirname, 'public', updateData[field].replace(/^\//, ''));
            if (!fs.existsSync(storedPath)) updateData[field] = '';
        }
        delete updateData[fileKey];
        delete updateData[removeKey];
    });

    // Processar Carousel do Hero
    let carouselItems = [];
    try {
        const carouselCount = parseInt(req.body.carousel_count || '0');
        for (let i = 0; i < carouselCount; i++) {
            let item = {
                image_desktop: req.body[`carousel_desktop_${i}`] || '',
                image_tablet: req.body[`carousel_tablet_${i}`] || '',
                image_mobile: req.body[`carousel_mobile_${i}`] || '',
                title: req.body[`carousel_title_${i}`] || '',
                description: req.body[`carousel_description_${i}`] || '',
                button_text: req.body[`carousel_button_text_${i}`] || '',
                layout_style: req.body[`carousel_layout_style_${i}`] || 'classic'
            };

            // Se remove foi checado
            if (req.body[`carousel_desktop_${i}_remove`] === '1') item.image_desktop = '';
            if (req.body[`carousel_tablet_${i}_remove`] === '1') item.image_tablet = '';
            if (req.body[`carousel_mobile_${i}_remove`] === '1') item.image_mobile = '';

            // Se subiu novos arquivos
            if (req.files && req.files[`hero_carousel_desktop_${i}_file`]) {
                item.image_desktop = `/uploads/${req.files[`hero_carousel_desktop_${i}_file`][0].filename}`;
            }
            if (req.files && req.files[`hero_carousel_tablet_${i}_file`]) {
                item.image_tablet = `/uploads/${req.files[`hero_carousel_tablet_${i}_file`][0].filename}`;
            }
            if (req.files && req.files[`hero_carousel_mobile_${i}_file`]) {
                item.image_mobile = `/uploads/${req.files[`hero_carousel_mobile_${i}_file`][0].filename}`;
            }

            carouselItems.push(item);
        }
        updateData.hero_carousel_json = JSON.stringify(carouselItems);
    } catch (e) {
        console.error('Erro ao processar carrossel do Hero:', e);
    }

    // 1. SINCRONIZAÇÃO DA TABELA DE BENEFÍCIOS (Independente do UPDATE principal)
    if (req.body.beneficios_json) {
        try {
            const items = JSON.parse(req.body.beneficios_json);
            console.log(`📦 Sincronizando ${items.length} benefícios...`);
            
            // Usar uma conexão única para garantir a ordem das operações
            const conn = await pool.getConnection();
            try {
                await conn.query('DELETE FROM beneficios');
                for (let i = 0; i < items.length; i++) {
                    const item = items[i];
                    if (item.icone || item.titulo || item.texto) {
                        await conn.query(
                            'INSERT INTO beneficios (icone, titulo, texto, ordem) VALUES (?, ?, ?, ?)', 
                            [item.icone || 'ri-checkbox-circle-line', item.titulo || '', item.texto || '', i]
                        );
                    }
                }
                console.log('✅ Tabela de benefícios sincronizada.');
            } finally {
                conn.release();
            }
        } catch (err) { 
            console.error('❌ ERRO NA TABELA BENEFICIOS:', err); 
        }
    }

    // Duas campanhas fixas da antiga seção de Benefícios.
    for (let i = 0; i < 2; i++) {
        const bannerId = req.body[`promotional_banner_${i}_id`];
        const title = (req.body[`promotional_banner_${i}_title`] || '').trim();
        const whatsappMessage = (req.body[`promotional_banner_${i}_whatsapp_message`] || '').trim();
        const currentImage = req.body[`promotional_banner_${i}_image`] || '';
        const uploaded = req.files && req.files[`promotional_banner_${i}_file`];
        const image = uploaded ? `/uploads/${uploaded[0].filename}` : currentImage;

        if (bannerId) {
            await pool.execute(
                'UPDATE banners SET titulo = ?, imagem = ?, texto_botao = ?, ordem = ?, ativo = 1, posicao = "promocional" WHERE id = ?',
                [title, image, whatsappMessage, i, bannerId]
            );
        } else if (image) {
            await pool.execute(
                'INSERT INTO banners (titulo, imagem, link, texto_botao, ordem, ativo, posicao) VALUES (?, ?, "", ?, ?, 1, "promocional")',
                [title, image, whatsappMessage, i]
            );
        }
    }

    // 2. FILTRAGEM E UPDATE DAS CONFIGURAÇÕES GLOBAIS
    try {
        await pool.execute(`
            INSERT INTO configuracoes_visuais (id, hamburger_color, social_icon_size)
            VALUES (1, ?, ?)
            ON DUPLICATE KEY UPDATE hamburger_color = VALUES(hamburger_color), social_icon_size = VALUES(social_icon_size)
        `, [updateData.hamburger_color || '#FFFFFF', updateData.social_icon_size || '1.25']);
    } catch (visualError) {
        console.error('Erro ao salvar configurações visuais do cabeçalho:', visualError.message);
    }

    let existingConfigColumns = new Set(validColumns);
    try {
        const [configColumns] = await pool.execute('SHOW COLUMNS FROM configuracoes_globais');
        existingConfigColumns = new Set(configColumns.map(col => col.Field));
    } catch (err) {
        console.error('Erro ao ler colunas de configuracoes_globais:', err.message);
    }
    const filteredData = {};
    const numericColumns = new Set([
        'smtp_port',
        'show_topbar',
        'hero_overlay_opacity',
        'hero_title_offset_y',
        'hero_button_offset_y',
        'hero_title_offset_y_desktop', 'hero_title_offset_y_tablet', 'hero_title_offset_y_mobile',
        'hero_button_offset_y_desktop', 'hero_button_offset_y_tablet', 'hero_button_offset_y_mobile',
        'title_size_hero_desktop', 'title_size_hero_tablet', 'title_size_hero_mobile',
        'title_size_page_desktop', 'title_size_page_tablet', 'title_size_page_mobile',
        'title_size_section_desktop', 'title_size_section_tablet', 'title_size_section_mobile',
        'title_size_card_desktop', 'title_size_card_tablet', 'title_size_card_mobile',
        'popup_border_radius'
    ]);
    validColumns.forEach(key => {
        // Ignoramos beneficios_json que já foi tratado, e só pegamos o que existe no updateData
        if (key !== 'beneficios_json' && updateData[key] !== undefined && existingConfigColumns.has(key)) {
            let val = updateData[key];
            if (Array.isArray(val)) {
                val = val[0];
            }
            if (numericColumns.has(key)) {
                val = val === '' || val === null ? null : Number(val);
                if (Number.isNaN(val)) val = null;
            }
            filteredData[key] = val;
        }
    });

    const fields = Object.keys(filteredData);
    console.log('🔍 Campos Finais para SQL:', fields);
    
    if(fields.length === 0) return res.redirect(cmsRedirect(req, 'success'));
    
    const sets = fields.map(f => `\`${f}\` = ?`).join(', ');
    const values = Object.values(filteredData);

    let sql = '';
    try {
        sql = `UPDATE configuracoes_globais SET ${sets} WHERE id = 1`;
        await pool.query(sql, values);
        res.redirect(cmsRedirect(req, 'success'));
    } catch (e) { 
        console.error('❌ CMS UPDATE ERROR:', e);
        const redirectUrl = cmsRedirect(req, 'error');
        const separator = redirectUrl.includes('?') ? '&' : '?';
        res.redirect(`${redirectUrl}${separator}message=${encodeURIComponent(e.sqlMessage || e.message || 'Erro ao salvar configuracoes.')}`);
    }
});

app.get('/admin/posts', async (req, res) => {
    const [posts] = await pool.execute('SELECT * FROM posts ORDER BY created_at DESC');
    res.render('admin/manage-posts', { title: 'CMS » Blog', posts });
});
app.get('/admin/posts/novo', (req, res) => res.render('admin/form-post', { title: 'Nova Publicação', post: null }));
app.post('/admin/posts', upload.single('imagem_file'), async (req, res) => {
    const { slug, titulo, categoria, resumo, conteudo, meta_title, meta_description, destaque_home, ordem, ativo } = req.body;
    let imagem = req.body.imagem;
    if (req.file) imagem = `/uploads/${req.file.filename}`;

    const destaque_home_val = (Array.isArray(destaque_home) ? destaque_home.includes('1') : destaque_home === '1') ? 1 : 0;
    const ativo_val = (Array.isArray(ativo) ? ativo.includes('1') : (ativo === '1' || ativo === undefined)) ? 1 : 0;

    try {
        await pool.execute('INSERT INTO posts (slug, titulo, categoria, data, resumo, imagem, conteudo, meta_title, meta_description, destaque_home, ordem, ativo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
            [slug, titulo, categoria, new Date().toLocaleDateString('pt-BR'), resumo, imagem, conteudo, meta_title, meta_description, destaque_home_val, parseInt(ordem) || 0, ativo_val]);
        res.redirect('/admin/posts?success=1');
    } catch (e) { 
        console.error('❌ POST SAVE ERROR:', e);
        res.redirect('/admin/posts/novo?error=1'); 
    }
});
app.get('/admin/posts/editar/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM posts WHERE id = ?', [req.params.id]);
        if (rows.length === 0) return res.redirect('/admin/posts');
        res.render('admin/form-post', { title: 'Editar Artigo', post: rows[0] });
    } catch (e) { res.redirect('/admin/posts'); }
});
app.post('/admin/posts/editar/:id', upload.single('imagem_file'), async (req, res) => {
    const { slug, titulo, categoria, resumo, conteudo, meta_title, meta_description, destaque_home, ordem, ativo } = req.body;
    let imagem = req.body.imagem;
    if (req.file) imagem = `/uploads/${req.file.filename}`;

    const destaque_home_val = (Array.isArray(destaque_home) ? destaque_home.includes('1') : destaque_home === '1') ? 1 : 0;
    const ativo_val = (Array.isArray(ativo) ? ativo.includes('1') : (ativo === '1' || ativo === undefined)) ? 1 : 0;

    try {
        await pool.execute('UPDATE posts SET slug=?, titulo=?, categoria=?, resumo=?, imagem=?, conteudo=?, meta_title=?, meta_description=?, destaque_home=?, ordem=?, ativo=? WHERE id=?', 
            [slug, titulo, categoria, resumo, imagem, conteudo, meta_title, meta_description, destaque_home_val, parseInt(ordem) || 0, ativo_val, req.params.id]);
        res.redirect('/admin/posts?success=1');
    } catch (e) { 
        console.error('❌ POST EDIT ERROR:', e);
        res.redirect(`/admin/posts/editar/${req.params.id}?error=1`); 
    }
});
app.post('/admin/posts/delete/:id', async (req, res) => {
    try {
        await pool.execute('DELETE FROM posts WHERE id = ?', [req.params.id]);
        res.redirect('/admin/posts?success=1');
    } catch (e) { res.redirect('/admin/posts?error=1'); }
});

// CRUD EQUIPE (CAPITAL HUMANO)
app.get('/admin/equipe', async (req, res) => {
    try {
        const [equipe] = await pool.execute('SELECT * FROM equipe ORDER BY ordem ASC, created_at DESC');
        res.render('admin/manage-team', { title: 'Gestão de Equipe', equipe, success: req.query.success });
    } catch (e) { res.send('Erro ao carregar equipe'); }
});
app.get('/admin/equipe/novo', (req, res) => res.render('admin/form-team', { title: 'Novo Membro', member: null }));
app.post('/admin/equipe', upload.single('imagem_file'), async (req, res) => {
    const { nome, funcao, ordem } = req.body;
    let imagem = req.body.imagem || '/img/placeholder-user.png';
    if (req.file) imagem = `/uploads/${req.file.filename}`;
    try {
        await pool.execute('INSERT INTO equipe (nome, funcao, imagem, ordem) VALUES (?, ?, ?, ?)', [nome, funcao, imagem, parseInt(ordem) || 0]);
        res.redirect('/admin/equipe?success=1');
    } catch (e) { 
        console.error('❌ TEAM SAVE ERROR:', e);
        res.redirect('/admin/equipe/novo?error=1'); 
    }
});
app.get('/admin/equipe/editar/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM equipe WHERE id = ?', [req.params.id]);
        if (rows.length === 0) return res.redirect('/admin/equipe');
        res.render('admin/form-team', { title: 'Editar Membro', member: rows[0] });
    } catch (e) { res.redirect('/admin/equipe'); }
});
app.post('/admin/equipe/editar/:id', upload.single('imagem_file'), async (req, res) => {
    const { nome, funcao, ordem } = req.body;
    let imagem = req.body.imagem;
    if (req.file) imagem = `/uploads/${req.file.filename}`;
    try {
        await pool.execute('UPDATE equipe SET nome=?, funcao=?, imagem=?, ordem=? WHERE id=?', [nome, funcao, imagem, parseInt(ordem) || 0, req.params.id]);
        res.redirect('/admin/equipe?success=1');
    } catch (e) { 
        console.error('❌ TEAM EDIT ERROR:', e);
        res.redirect(`/admin/equipe/editar/${req.params.id}?error=1`); 
    }
});
app.post('/admin/equipe/delete/:id', async (req, res) => {
    try {
        await pool.execute('DELETE FROM equipe WHERE id = ?', [req.params.id]);
        res.redirect('/admin/equipe?success=1');
    } catch (e) { res.redirect('/admin/equipe?error=1'); }
});

// Admin: Especialidades (servicos) reativado para o projeto
app.get('/admin/banners', async (req, res) => {
    const [banners] = await pool.execute('SELECT * FROM banners ORDER BY ordem ASC, created_at DESC');
    res.render('admin/banners', { title: 'CMS » Banners Rotativos', banners, query: req.query });
});
app.post('/admin/banners', upload.single('imagem_file'), async (req, res) => {
    try {
        const imagem = req.file ? `/uploads/${req.file.filename}` : req.body.imagem;
        if (!imagem) return res.redirect('/admin/banners?error=imagem');
        const { titulo, link, texto_botao, ordem, posicao } = req.body;
        if (posicao === 'promocional') {
            const [[{ total }]] = await pool.execute('SELECT COUNT(*) AS total FROM banners WHERE posicao = "promocional"');
            if (total >= 2) return res.redirect('/admin/banners?error=limite_promocional');
        }
        await pool.execute(
            'INSERT INTO banners (titulo, imagem, link, texto_botao, ordem, ativo, posicao) VALUES (?, ?, ?, ?, ?, 1, ?)',
            [titulo || '', imagem, link || '', texto_botao || '', parseInt(ordem) || 0, posicao === 'promocional' ? 'promocional' : 'topo']
        );
        res.redirect('/admin/banners?success=1');
    } catch (error) {
        console.error('Error adding banner:', error);
        res.redirect('/admin/banners?error=1&message=' + encodeURIComponent('Erro ao salvar o banner no banco de dados.'));
    }
});
app.post('/admin/banners/toggle/:id', async (req, res) => {
    await pool.execute('UPDATE banners SET ativo = NOT ativo WHERE id = ?', [req.params.id]);
    res.redirect('/admin/banners?success=1');
});
app.post('/admin/banners/delete/:id', async (req, res) => {
    await pool.execute('DELETE FROM banners WHERE id = ?', [req.params.id]);
    res.redirect('/admin/banners?success=1');
});

app.get('/admin/servicos', async (req, res) => {
    const [services] = await pool.execute('SELECT * FROM servicos ORDER BY created_at DESC');
    res.render('admin/manage-services', { title: 'CMS » Produtos e Ofertas', services });
});
app.get('/admin/servicos/novo', (req, res) => res.render('admin/form-service', { title: 'Novo Produto', service: null }));
app.post('/admin/servicos', upload.single('imagem_file'), async (req, res) => {
    const { slug, titulo, resumo, conteudo, icone, meta_title, meta_description, destaque_home, ordem, ativo, preco_de, preco_por, unidade, selo } = req.body;
    let imagem = req.body.imagem;
    if (req.file) imagem = `/uploads/${req.file.filename}`;

    const destaque_home_val = (Array.isArray(destaque_home) ? destaque_home.includes('1') : destaque_home === '1') ? 1 : 0;
    const ativo_val = (Array.isArray(ativo) ? ativo.includes('1') : (ativo === '1' || ativo === undefined)) ? 1 : 0;

    try {
        await pool.execute('INSERT INTO servicos (slug, titulo, resumo, imagem, conteudo, icone, meta_title, meta_description, destaque_home, ordem, ativo, preco_de, preco_por, unidade, selo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
            [slug, titulo, resumo || '', imagem, conteudo || '', icone || 'ri-shopping-bag-line', meta_title, meta_description, destaque_home_val, parseInt(ordem) || 0, ativo_val, preco_de || null, preco_por || null, unidade || '', selo || '']);
        res.redirect('/admin/servicos?success=1');
    } catch (e) { 
        console.error('❌ SERVICE SAVE ERROR:', e);
        res.redirect('/admin/servicos/novo?error=1'); 
    }
});
app.get('/admin/servicos/editar/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM servicos WHERE id = ?', [req.params.id]);
        if (rows.length === 0) return res.redirect('/admin/servicos');
        res.render('admin/form-service', { title: 'Editar Produto', service: rows[0] });
    } catch (e) { res.redirect('/admin/servicos'); }
});
app.post('/admin/servicos/editar/:id', upload.single('imagem_file'), async (req, res) => {
    const { slug, titulo, resumo, conteudo, icone, meta_title, meta_description, destaque_home, ordem, ativo, preco_de, preco_por, unidade, selo } = req.body;
    let imagem = req.body.imagem;
    if (req.file) imagem = `/uploads/${req.file.filename}`;

    const destaque_home_val = (Array.isArray(destaque_home) ? destaque_home.includes('1') : destaque_home === '1') ? 1 : 0;
    const ativo_val = (Array.isArray(ativo) ? ativo.includes('1') : (ativo === '1' || ativo === undefined)) ? 1 : 0;

    try {
        await pool.execute('UPDATE servicos SET slug=?, titulo=?, resumo=?, imagem=?, conteudo=?, icone=?, meta_title=?, meta_description=?, destaque_home=?, ordem=?, ativo=?, preco_de=?, preco_por=?, unidade=?, selo=? WHERE id=?', 
            [slug, titulo, resumo || '', imagem, conteudo || '', icone || 'ri-shopping-bag-line', meta_title, meta_description, destaque_home_val, parseInt(ordem) || 0, ativo_val, preco_de || null, preco_por || null, unidade || '', selo || '', req.params.id]);
        res.redirect('/admin/servicos?success=1');
    } catch (e) { 
        console.error('❌ SERVICE EDIT ERROR:', e);
        res.redirect(`/admin/servicos/editar/${req.params.id}?error=1`); 
    }
});
app.post('/admin/servicos/delete/:id', async (req, res) => {
    try {
        await pool.execute('DELETE FROM servicos WHERE id = ?', [req.params.id]);
        res.redirect('/admin/servicos?success=1');
    } catch (e) { res.redirect('/admin/servicos?error=1'); }
});

// --- Banco de Imagens (Mídia) ---
app.get('/admin/api/midias', async (req, res) => {
    try {
        const dir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(dir)) return res.json([]);
        const files = fs.readdirSync(dir).map(file => {
            const filepath = path.join(dir, file);
            const stats = fs.statSync(filepath);
            return { name: file, url: `/uploads/${file}`, size: stats.size, mtime: stats.mtime };
        }).filter(file => /\.(jpg|jpeg|png|webp|gif|svg)$/i.test(file.name))
          .sort((a, b) => new Date(b.mtime) - new Date(a.mtime));
        res.json(files);
    } catch (error) {
        console.error('Erro ao listar o banco de mídias:', error);
        res.status(500).json({ error: 'Erro ao carregar as imagens.' });
    }
});

app.get('/admin/midia', async (req, res) => {
    try {
        const fs = require('fs');
        const path = require('path');
        const dir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        
        const files = fs.readdirSync(dir).map(file => {
            const stats = fs.statSync(path.join(dir, file));
            return {
                name: file,
                url: '/uploads/' + file,
                size: (stats.size / 1024).toFixed(1) + ' KB',
                mtime: stats.mtime
            };
        }).filter(f => f.name.match(/\.(jpg|jpeg|png|webp|gif|svg)$/i))
          .sort((a, b) => b.mtime - a.mtime);

        res.render('admin/midia', { title: 'Banco de Imagens', files });
    } catch (e) {
        console.error(e);
        res.redirect('/admin/dashboard?error=1');
    }
});

app.post('/admin/midia/upload', upload.single('imagem_file'), (req, res) => {
    res.redirect('/admin/midia?success=1');
});

app.post('/admin/midia/delete', express.urlencoded({ extended: true }), (req, res) => {
    try {
        const fs = require('fs');
        const path = require('path');
        const { filename } = req.body;
        if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return res.redirect('/admin/midia?error=1');
        }
        
        const filepath = path.join(__dirname, 'public', 'uploads', filename);
        if (fs.existsSync(filepath)) {
            fs.unlinkSync(filepath);
        }
        res.redirect('/admin/midia?success=1');
    } catch (e) {
        res.redirect('/admin/midia?error=1');
    }
});


// app.get('/contato', (req, res) => res.render('contato', { title: 'Contato | Sua Empresa' }));
app.get('/politica-de-privacidade', (req, res) => {
    const siteName = res.locals.settings?.site_name || 'Sua Empresa';
    res.render('politica', {
        title: `Política de Privacidade | ${siteName}`,
        description: `Entenda como a ${siteName} coleta, utiliza e protege os dados pessoais enviados pelo site.`
    });
});
app.get('/termos-e-condicoes', (req, res) => {
    const siteName = res.locals.settings?.site_name || 'Sua Empresa';
    res.render('termos', {
        title: `Termos e Condições | ${siteName}`,
        description: `Consulte os termos e condições de uso do site e dos conteúdos digitais da ${siteName}.`
    });
});

// APIS
app.use('/api/auth/login', loginRateLimit);
app.use(['/api/leads', '/api/newsletter', '/api/depoimentos', '/api/comentarios'], publicFormRateLimit);
app.use('/api/auth', require('./routes/auth'));
app.use('/api/leads', require('./routes/leads'));
app.use('/api/newsletter', require('./routes/newsletter'));
app.use('/admin/usuarios', require('./routes/usuarios'));

// ADMIN DASHBOARD
app.get('/admin/login', (req, res) => res.render('admin/login', { title: 'Login Admin' }));
app.get('/admin/dashboard', async (req, res) => {
    try {
        const [l] = await pool.execute('SELECT COUNT(*) as n FROM contatos');
        const [n] = await pool.execute('SELECT COUNT(*) as n FROM newsletter');
        
        // Busca conversões dos últimos 6 meses (Leads + Newsletter)
        const [monthlyData] = await pool.execute(`
            SELECT mes, SUM(qtd) as qtd FROM (
                SELECT DATE_FORMAT(created_at, '%b') as mes, DATE_FORMAT(created_at, '%m') as mes_num, COUNT(*) as qtd 
                FROM contatos 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY mes, mes_num
                UNION ALL
                SELECT DATE_FORMAT(created_at, '%b') as mes, DATE_FORMAT(created_at, '%m') as mes_num, COUNT(*) as qtd 
                FROM newsletter 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY mes, mes_num
            ) as combined
            GROUP BY mes, mes_num
            ORDER BY mes_num ASC
        `);

        res.render('admin/dashboard', { 
            title: 'Dashboard', 
            leads: l[0].n, 
            news: n[0].n, 
            chartData: monthlyData 
        });
    } catch (e) { 
        console.error('❌ DASHBOARD ERROR:', e);
        res.render('admin/dashboard', { title: 'Dashboard', leads: 0, news: 0, chartData: [] }); 
    }
});

app.get('/admin/leads', async (req, res) => {
    try {
        const [leads] = await pool.execute('SELECT * FROM contatos ORDER BY created_at DESC');
        res.render('admin/leads', { title: 'Gestão de Leads', leads });
    } catch (e) { res.send('Erro ao carregar leads'); }
});

app.post('/admin/leads/delete/:id', async (req, res) => {
    try {
        await pool.execute('DELETE FROM contatos WHERE id = ?', [req.params.id]);
        res.redirect('/admin/leads');
    } catch (e) { res.redirect('/admin/leads'); }
});

app.get('/admin/newsletter', async (req, res) => {
    try {
        const [emails] = await pool.execute('SELECT * FROM newsletter ORDER BY created_at DESC');
        res.render('admin/newsletter', { title: 'Newsletter', emails });
    } catch (e) { res.send('Erro ao carregar newsletter'); }
});

app.post('/admin/newsletter/delete/:id', async (req, res) => {
    try {
        await pool.execute('DELETE FROM newsletter WHERE id = ?', [req.params.id]);
        res.redirect('/admin/newsletter');
    } catch (e) { res.redirect('/admin/newsletter'); }
});

app.get('/admin/config', async (req, res) => {
    try {
        const [config] = await pool.execute('SELECT * FROM configuracoes_globais LIMIT 1');
        res.render('admin/config', { title: 'Configurações Globais', settings: config[0] || {} });
    } catch (e) { res.render('admin/config', { title: 'Configurações', settings: {} }); }
});

app.post('/admin/config', async (req, res) => {
    const { 
        whatsapp, cnpj, endereco, meta_title_home, meta_description_home, meta_keywords,
        facebook_pixel, google_analytics, pinterest_pixel, linkedin_pixel,
        custom_head_code, custom_body_code, smtp_host, smtp_port, smtp_user, smtp_pass,
        email_reply_contact, email_reply_newsletter, email_subject_contact, email_subject_newsletter
    } = req.body;
    const query = `
        UPDATE configuracoes_globais SET 
        whatsapp = ?, cnpj = ?, endereco = ?, meta_title_home = ?, meta_description_home = ?, meta_keywords = ?,
        facebook_pixel = ?, google_analytics = ?, pinterest_pixel = ?, linkedin_pixel = ?,
        custom_head_code = ?, custom_body_code = ?, smtp_host = ?, smtp_port = ?, smtp_user = ?, smtp_pass = ?,
        email_reply_contact = ?, email_reply_newsletter = ?, email_subject_contact = ?, email_subject_newsletter = ?
        WHERE id = 1
    `;
    try {
        await pool.execute(query, [
            whatsapp, cnpj, endereco, meta_title_home, meta_description_home, meta_keywords,
            facebook_pixel, google_analytics, pinterest_pixel, linkedin_pixel,
            custom_head_code, custom_body_code, smtp_host, parseInt(smtp_port) || null, smtp_user, smtp_pass,
            email_reply_contact, email_reply_newsletter, email_subject_contact, email_subject_newsletter
        ]);
        res.redirect('/admin/config?success=1');
    } catch (e) { 
        console.error('❌ CONFIG SAVE ERROR:', e);
        res.redirect('/admin/config?error=1'); 
    }
});

app.get('/admin/perfil', async (req, res) => {
    try {
        const [user] = await pool.execute('SELECT nome, email FROM usuarios WHERE id = 1');
        const [config] = await pool.execute('SELECT whatsapp FROM configuracoes_globais WHERE id = 1');
        
        // Defesa: Caso o ID 1 tenha sido alterado/removido
        const userData = user[0] || { nome: 'Administrador', email: 'admin@teste.com' };

        res.render('admin/perfil', { 
            title: 'Meu Perfil', 
            user: userData, 
            whatsapp: config[0]?.whatsapp || '',
            success: req.query.success,
            error: req.query.error
        });
    } catch (e) { res.redirect('/admin/dashboard'); }
});

app.post('/admin/perfil', async (req, res) => {
    const { nome, email, senha, whatsapp } = req.body;
    try {
        await pool.execute('UPDATE usuarios SET nome = ?, email = ? WHERE id = 1', [nome, email]);
        if (senha && senha.trim() !== '') {
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(senha, salt);
            await pool.execute('UPDATE usuarios SET senha = ? WHERE id = 1', [hashed]);
        }
        await pool.execute('UPDATE configuracoes_globais SET whatsapp = ? WHERE id = 1', [whatsapp]);
        res.redirect('/admin/perfil?success=1');
    } catch (e) { res.redirect('/admin/perfil?error=1'); }
});

// GESTÃO DE COMENTÁRIOS (ADMIN)
app.get('/admin/comentarios', async (req, res) => {
    try {
        const [comentarios] = await pool.execute('SELECT * FROM comentarios ORDER BY created_at DESC');
        res.render('admin/comentarios', { title: 'Moderação de Comentários', comentarios });
    } catch (e) { res.redirect('/admin/dashboard'); }
});
app.post('/admin/comentarios/aprovar/:id', async (req, res) => {
    await pool.execute('UPDATE comentarios SET aprovado = TRUE WHERE id = ?', [req.params.id]);
    res.redirect('/admin/comentarios');
});
app.post('/admin/comentarios/delete/:id', async (req, res) => {
    await pool.execute('DELETE FROM comentarios WHERE id = ?', [req.params.id]);
    res.redirect('/admin/comentarios');
});

// GESTÃO DE DEPOIMENTOS (ADMIN)
app.get('/admin/depoimentos', async (req, res) => {
    try {
        const [depoimentos] = await pool.execute('SELECT * FROM depoimentos ORDER BY created_at DESC');
        const [googleReviews] = await pool.execute('SELECT * FROM google_reviews ORDER BY review_time DESC, updated_at DESC LIMIT 50');
        const [reviewRows] = await pool.execute('SELECT * FROM reviews_widget_settings WHERE id = 1');
        const [connectionRows] = await pool.execute('SELECT * FROM reviews_google_connection WHERE id = 1');
        const activeReviews = googleReviews.filter(review => Boolean(review.ativo));
        res.render('admin/depoimentos', {
            title: 'Gestor de Avaliações', depoimentos, googleReviews,
            reviewSettings: reviewRows[0] || {}, connectedPlace: connectionRows[0] ? {
                id: connectionRows[0].place_id, name: connectionRows[0].business_name,
                address: connectionRows[0].business_address, url: connectionRows[0].google_url,
                rating: connectionRows[0].rating, count: connectionRows[0].review_count,
                connectedAt: connectionRows[0].connected_at
            } : null,
            placesApiConfigured: Boolean(googlePlacesApiKey()),
            reviewStats: { total: googleReviews.length, active: activeReviews.length,
                average: (activeReviews.length ? activeReviews.reduce((sum, r) => sum + Number(r.rating || 0), 0) / activeReviews.length : 0).toFixed(1),
                lastSync: googleReviews[0]?.updated_at || null },
            googleSyncSuccess: req.query.google_sync === 'success',
            googleSyncError: req.query.google_sync === 'error' ? req.query.message : null,
            googleSyncSaved: req.query.saved, googleSyncReceived: req.query.received,
            saved: req.query.saved_settings === '1', connectionSuccess: req.query.connected === '1',
            connectionError: req.query.connection_error || null
        });
    } catch (e) { res.redirect('/admin/dashboard'); }
});
app.post('/admin/depoimentos/connect-google', async (req, res) => {
    try {
        const place = await getPlaceDetails(req.body.google_place || '');
        const [currentConnection] = await pool.execute(
            'SELECT place_id FROM reviews_google_connection WHERE id = 1'
        );
        const isChangingPlace = Boolean(
            currentConnection[0]?.place_id && currentConnection[0].place_id !== place.id
        );

        // As avaliacoes do Google ficam em cache. Ao trocar de empresa, limpe o
        // cache anterior para nao misturar depoimentos de dois estabelecimentos.
        if (isChangingPlace) {
            await pool.execute('DELETE FROM google_reviews');
        }
        await pool.execute(`INSERT INTO reviews_google_connection
            (id, place_id, business_name, business_address, google_url, write_review_url, rating, review_count, connected_at)
            VALUES (1,?,?,?,?,?,?,?,NOW()) ON DUPLICATE KEY UPDATE place_id=VALUES(place_id),
            business_name=VALUES(business_name), business_address=VALUES(business_address), google_url=VALUES(google_url),
            write_review_url=VALUES(write_review_url), rating=VALUES(rating), review_count=VALUES(review_count), connected_at=NOW()`,
            [place.id, place.displayName?.text || 'Empresa no Google', place.formattedAddress || '',
             place.googleMapsUri || '', place.googleMapsLinks?.writeAReviewUri || null,
             Number(place.rating || 0), Number(place.userRatingCount || 0)]);
        const result = await savePlacesReviews(place);
        res.redirect(`/admin/depoimentos?connected=1&saved=${result.saved}#conectar`);
    } catch (e) {
        res.redirect(`/admin/depoimentos?connection_error=${encodeURIComponent(e.message)}#conectar`);
    }
});
app.post('/admin/depoimentos/disconnect-google', async (req, res) => {
    await pool.execute('DELETE FROM reviews_google_connection WHERE id = 1');
    res.redirect('/admin/depoimentos#conectar');
});
app.post('/admin/depoimentos/google/:id/toggle', async (req, res) => {
    await pool.execute('UPDATE google_reviews SET ativo = NOT ativo WHERE id = ?', [req.params.id]);
    res.redirect('/admin/depoimentos#avaliacoes');
});

app.post('/admin/midia/delete-bulk', express.urlencoded({ extended: true }), (req, res) => {
    try {
        const uploadsDir = path.resolve(__dirname, 'public', 'uploads');
        const submitted = Array.isArray(req.body.filenames) ? req.body.filenames : [req.body.filenames];
        const filenames = [...new Set(submitted.filter(Boolean))].slice(0, 500);
        let deleted = 0;

        for (const filename of filenames) {
            if (typeof filename !== 'string' || path.basename(filename) !== filename || !/\.(jpg|jpeg|png|webp|gif|svg)$/i.test(filename)) continue;
            const filepath = path.resolve(uploadsDir, filename);
            if (path.dirname(filepath) !== uploadsDir || !fs.existsSync(filepath) || !fs.statSync(filepath).isFile()) continue;
            fs.unlinkSync(filepath);
            deleted++;
        }

        res.redirect(`/admin/midia?success=1&deleted=${deleted}`);
    } catch (e) {
        console.error('Erro ao excluir mídias em massa:', e);
        res.redirect('/admin/midia?error=1');
    }
});
app.post('/admin/depoimentos/google/:id/delete', async (req, res) => {
    const [rows] = await pool.execute('SELECT review_id FROM google_reviews WHERE id = ?', [req.params.id]);
    if (rows[0]?.review_id) {
        await pool.execute('INSERT IGNORE INTO google_reviews_deleted (review_id) VALUES (?)', [rows[0].review_id]);
        await pool.execute('DELETE FROM google_reviews WHERE id = ?', [req.params.id]);
    }
    res.redirect('/admin/depoimentos#avaliacoes');
});
app.post('/admin/depoimentos/widget', async (req, res) => {
    const layouts = new Set(['slider','grid','list']);
    const themes = new Set(['light','dark','minimal']);
    const color = value => /^#[0-9a-f]{6}$/i.test(value || '') ? value : null;
    await pool.execute(`UPDATE reviews_widget_settings SET reviews_widget_layout=?, reviews_widget_theme=?,
        reviews_widget_min_rating=?, reviews_widget_limit=?, reviews_widget_show_photos=?,
        reviews_widget_show_date=?, reviews_widget_autoplay=?, reviews_widget_bg=?,
        reviews_widget_card_bg=?, reviews_widget_accent=? WHERE id=1`, [
        layouts.has(req.body.layout) ? req.body.layout : 'slider', themes.has(req.body.theme) ? req.body.theme : 'light',
        Math.min(5, Math.max(1, parseInt(req.body.min_rating,10)||4)), Math.min(20, Math.max(1, parseInt(req.body.limit,10)||8)),
        req.body.show_photos ? 1:0, req.body.show_date ? 1:0, req.body.autoplay ? 1:0,
        color(req.body.background)||'#FFFFFF', color(req.body.card_background)||'#F7F7F4', color(req.body.accent)||'#F59E0B'
    ]);
    res.redirect('/admin/depoimentos?saved_settings=1#widget');
});
app.post('/admin/depoimentos/sync-google', async (req, res) => {
    try {
        const result = await syncGoogleReviews();
        res.redirect(`/admin/depoimentos?google_sync=success&saved=${result.saved}&received=${result.received}`);
    } catch (e) {
        console.error('GOOGLE REVIEWS SYNC ERROR:', e.message);
        res.redirect(`/admin/depoimentos?google_sync=error&message=${encodeURIComponent(e.message)}`);
    }
});
app.post('/admin/depoimentos/aprovar/:id', async (req, res) => {
    await pool.execute('UPDATE depoimentos SET aprovado = TRUE WHERE id = ?', [req.params.id]);
    res.redirect('/admin/depoimentos');
});
app.post('/admin/depoimentos/delete/:id', async (req, res) => {
    await pool.execute('DELETE FROM depoimentos WHERE id = ?', [req.params.id]);
    res.redirect('/admin/depoimentos');
});

// FORMULÁRIO EXTERNO DE DEPOIMENTOS (PÚBLICO)
app.get('/depoimentos/novo', (req, res) => {
    res.render('form-depoimento', { title: 'Enviar Depoimento | Sua Empresa' });
});
app.post('/api/depoimentos', upload.single('foto'), async (req, res) => {
    const { nome, cargo, empresa, texto } = req.body;
    const foto = req.file ? `/uploads/${req.file.filename}` : null;
    try {
        await pool.execute('INSERT INTO depoimentos (nome, cargo, empresa, texto, foto) VALUES (?, ?, ?, ?, ?)', [nome, cargo, empresa, texto, foto]);
        res.redirect('/depoimentos/novo?success=1');
    } catch (e) { res.redirect('/depoimentos/novo?error=1'); }
});

// SUBMISSÃO DE COMENTÁRIO (PÚBLICO)
app.post('/api/comentarios', async (req, res) => {
    const { post_id, nome, email, comentario } = req.body;
    try {
        await pool.execute('INSERT INTO comentarios (post_id, nome, email, comentario) VALUES (?, ?, ?, ?)', [post_id, nome, email, comentario]);
        res.redirect(`/blog/${post_id}?success=comment`);
    } catch (e) { res.redirect(`/blog/${post_id}?error=comment`); }
});

// API Pública de Busca de Filiais
app.get('/api/filiais/search', async (req, res) => {
    const { bairro, cidade, estado } = req.query;
    try {
        const [rows] = await pool.execute('SELECT * FROM filiais');
        // Buscar por bairro (match parcial) ou cidade inteira se não tiver bairro específico
        let match = rows.find(f => {
            if (f.bairros && f.bairros.trim()) {
                const bairrosList = f.bairros.split(',').map(b => b.trim().toLowerCase());
                return bairrosList.includes((bairro||'').toLowerCase()) && f.cidade.toLowerCase() === (cidade||'').toLowerCase();
            }
            // Se a filial não definiu bairro, atende a cidade toda
            return f.cidade.toLowerCase() === (cidade||'').toLowerCase() && f.estado.toLowerCase() === (estado||'').toLowerCase();
        });
        
        if (match) return res.json({ success: true, link: match.link });
        res.json({ success: false, message: 'Nenhuma loja encontrada para esta região.' });
    } catch (e) {
        res.json({ success: false, message: 'Erro ao buscar filiais.' });
    }
});

// Admin: Criar/Editar Filial
app.post('/admin/filiais', async (req, res) => {
    const { id, nome, cidade, estado, bairros, link } = req.body;
    try {
        if (id) {
            await pool.execute('UPDATE filiais SET nome=?, cidade=?, estado=?, bairros=?, link=? WHERE id=?', [nome, cidade, estado, bairros, link, id]);
        } else {
            await pool.execute('INSERT INTO filiais (nome, cidade, estado, bairros, link) VALUES (?, ?, ?, ?, ?)', [nome, cidade, estado, bairros, link]);
        }
        res.redirect('/admin/conteudo?tab=tab-lojas&success=1');
    } catch (e) {
        console.error(e);
        res.redirect('/admin/conteudo?tab=tab-lojas&error=1');
    }
});

// Admin: Deletar Filial
app.post('/admin/filiais/delete/:id', async (req, res) => {
    try {
        await pool.execute('DELETE FROM filiais WHERE id=?', [req.params.id]);
        res.redirect('/admin/conteudo?tab=tab-lojas&success=1');
    } catch (e) {
        res.redirect('/admin/conteudo?tab=tab-lojas&error=1');
    }
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError || err.message === 'Tipo de arquivo nao permitido.') {
        const wantsJson = req.xhr || (req.headers.accept || '').includes('application/json');
        if (wantsJson) {
            return res.status(400).json({ msg: err.message });
        }
        if (req.originalUrl && req.originalUrl.startsWith('/admin/conteudo')) {
            return res.redirect(cmsRedirect(req, 'error'));
        }
        return res.redirect(`${req.headers.referer || '/'}?error=upload`);
    }
    next(err);
});

app.use((req, res) => renderNotFound(res));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Sistema SISTEMA ON: Porta ${PORT}`);
});
