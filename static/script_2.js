var map = L.map('map').setView([50.4501, 30.5234], 6);
var markers = [];

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 18,
}).addTo(map);

function updateTimelineLabel(year) {
    document.getElementById('timelineLabel').textContent = year;
    document.getElementById('timelineInput').value = year;
    loadEventsForYear(year);
}

function updateTimelineFromInput() {
    var year = document.getElementById('timelineInput').value;
    if (year >= 1000 && year <= 2024) {
        document.getElementById('timeline').value = year;
        updateTimelineLabel(year);
    }
}

function loadEventsForYear(year) {
    eventsList.innerHTML = '';
    fetch(`/api/events?year=${year}`)
        .then(response => response.json())
        .then(events => {
            map.eachLayer(layer => {
                if (layer instanceof L.Marker) {
                    map.removeLayer(layer);
                }
            });

            addMarkers(events);
        })
        .catch(error => console.error('Error loading events:', error));
}

function handleSearchFormSubmit(e) {
    e.preventDefault();
    var searchForm = document.querySelector('#searchForm');
    var query = document.querySelector('#searchForm input[name="query"]').value;

    fetch(`/api/search?query=${encodeURIComponent(query)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(events => {
            console.log('Search results:', events);
            displaySearchResults(events);
            addMarkers(events);
        })
        .catch(error => console.error('Error searching events:', error))
        .finally(() => {
            searchForm.reset();
        });
}

document.querySelector('#searchForm').addEventListener('submit', handleSearchFormSubmit);


function addMarkers(events) {
    markers.forEach(marker => map.removeLayer(marker));
    markers = [];

    events.forEach(event => {
        var imageUrl = event.image ? correctImageUrl(event.image) : '';

        console.log('Image URL:', imageUrl);

        var marker = L.marker([event.latitude, event.longitude]).addTo(map)
            .bindPopup(`
                <b>${event.name}</b><br>
                ${event.date}<br>
                ${imageUrl ? `<img src="${imageUrl}" alt="Event Image" style="width: 100px; height: auto;"><br>` : ''}
                <a href="/event/${event.id}">Деталі</a>
            `);

        markers.push(marker);
    });
}


function correctImageUrl(imageUrl) {
    var baseImageUrl = '/uploads/';

    if (imageUrl.startsWith(baseImageUrl)) {
        return imageUrl;
    }

    return baseImageUrl + imageUrl;
}


function displaySearchResults(events) {
    const eventsList = document.getElementById('eventsList');
    eventsList.innerHTML = '';

    events.forEach(event => {
        const imageUrl = correctImageUrl(event.image); 

        const eventElement = document.createElement('div');
        eventElement.className = 'card';
        eventElement.innerHTML = `
            ${imageUrl ? `<img src="${imageUrl}" alt="Event Image" class="card-img-top"><br>` : ''}
            <h3 class="card-title">${event.name}</h3> <!-- Додайте клас заголовка -->
            <p class="card-text"><strong>Дата:</strong> ${event.date}</p> 
            <a href="/event/${event.id}" class="card-text">Деталі</a>
        `;
        eventsList.appendChild(eventElement);
    });
}


function toggleTheme() {
    document.body.classList.toggle('dark-theme');
}

map.on('click', function(e) {
    document.getElementById('latitude').value = e.latlng.lat;
    document.getElementById('longitude').value = e.latlng.lng;
});

function addEvent(eventData) {
    var formData = new FormData(document.getElementById('addEventForm'));

    fetch('/api/add_event', {
        method: 'POST',
        body: formData,
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            var imageUrl = `app/uploads/${formData.get('image').name}`;
            L.marker([eventData.latitude, eventData.longitude]).addTo(map)
                .bindPopup(`
                    <b>${eventData.name}</b><br>
                    ${eventData.description}<br>
                    ${eventData.date}<br>
                    ${imageUrl ? `<img src="${imageUrl}" alt="Event Image" style="width: 100px; height: auto;"><br>` : ''}
                    <a href="/event/${data.event_id}">Деталі</a>
                `);
            loadEventsForYear(document.getElementById('timeline').value);
        }
    })
    .catch(error => console.error('Error adding event:', error));
}

document.getElementById('addEventForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var eventData = {
        name: document.getElementById('name').value,
        description: document.getElementById('description').value,
        date: document.getElementById('date').value,
        latitude: parseFloat(document.getElementById('latitude').value),
        longitude: parseFloat(document.getElementById('longitude').value)
    };

    addEvent(eventData);
});

document.addEventListener('DOMContentLoaded', function() {
    loadEventsForYear(document.getElementById('timeline').value);
    fetchEvents();
    fetchTopResults(); 
});

function fetchEvents() {
    fetch('/api/events')
        .then(response => response.json())
        .then(events => {
            displaySearchResults(events);
        })
        .catch(error => console.error('Error fetching events:', error));
}

function fetchTopResults() {
    var topResults = [
        { name: "Иван Иванов", score: 95, time: "10:30", latitude: 50.4501, longitude: 30.5234 },
        { name: "Анна Смирнова", score: 90, time: "12:15", latitude: 50.3511, longitude: 30.6324 },
        { name: "Петр Петров", score: 85, time: "11:45", latitude: 50.2512, longitude: 30.7235 }
    ];

    displayTopResultsOnMap(topResults);
}

function displayTopResultsOnMap(topResults) {
    topResults.forEach(result => {
        L.marker([result.latitude, result.longitude]).addTo(map)
            .bindPopup(` 
                <b>${result.name}</b><br>
                Балли: ${result.score}<br>
                Час проходження: ${result.time}<br>
            `);
    });
}

document.getElementById('searchForm').addEventListener('submit', handleSearchFormSubmit);
