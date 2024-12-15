<!DOCTYPE html>
<html data-bs-theme="light" lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, shrink-to-fit=no">
    <title>OSCO - Admin Dashboard</title>
    <link rel="stylesheet" href="src/assets/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter:300italic,400italic,600italic,700italic,800italic,400,300,600,700,800&amp;display=swap">
    <link rel="stylesheet" href="src/assets/css/accordion-faq-list.css">
    <link rel="stylesheet" href="src/assets/css/Custom.css">
    <link rel="stylesheet" href="src/assets/css/dropdown-search-bs4.css">
    <link rel="stylesheet" href="src/assets/css/Table-With-Search-search-table.css">
    <link rel="stylesheet" href="src/assets/css/Table-With-Search.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .card-body {
            padding: 1rem;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 20px;
        }
        .container-wide {
            max-width: 90%; /* Adjust this value as needed */
            padding: 2rem;
            border-radius: 10px; /* Optional: to keep the rounded corners */
            margin: 0 auto; /* Center the container */
        }
    </style>
</head>

<body>
    <nav class="navbar navbar-expand-md sticky-top py-3 navbar-dark" id="mainNav">
        <div class="container"><a class="navbar-brand d-flex align-items-center" href="/"><span class="bs-icon-sm bs-icon-circle bs-icon-primary shadow d-flex justify-content-center align-items-center me-2 bs-icon"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="currentColor" viewBox="0 0 16 16" class="bi bi-bezier">
                        <path fill-rule="evenodd" d="M0 10.5A1.5 1.5 0 0 1 1.5 9h1A1.5 1.5 0 0 1 4 10.5v1A1.5 1.5 0 0 1 2.5 13h-1A1.5 1.5 0 0 1 0 11.5zm1.5-.5a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5zm10.5.5A1.5 1.5 0 0 1 13.5 9h1a1.5 1.5 0 0 1 1.5 1.5v1a1.5 1.5 0 0 1-1.5 1.5h-1a1.5 1.5 0 0 1-1.5-1.5zm1.5-.5a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5zM6 4.5A1.5 1.5 0 0 1 7.5 3h1A1.5 1.5 0 0 1 10 4.5v1A1.5 1.5 0 0 1 8.5 7h-1A1.5 1.5 0 0 1 6 5.5zM7.5 4a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5z"></path>
                        <path d="M6 4.5H1.866a1 1 0 1 0 0 1h2.668A6.517 6.517 0 0 0 1.814 9H2.5c.123 0 .244.015.358.043a5.517 5.517 0 0 1 3.185-3.185A1.503 1.503 0 0 1 6 5.5zm3.957 1.358A1.5 1.5 0 0 0 10 5.5v-1h4.134a1 1 0 1 1 0 1h-2.668a6.517 6.517 0 0 1 2.72 3.5H13.5c-.123 0-.243.015-.358.043a5.517 5.517 0 0 0-3.185-3.185z"></path>
                    </svg></span><span>OSCO</span></a><button data-bs-toggle="collapse" class="navbar-toggler" data-bs-target="#navcol-1"><span class="visually-hidden">Toggle navigation</span><span class="navbar-toggler-icon"></span></button>
            <div class="collapse navbar-collapse" id="navcol-1">
                <ul class="navbar-nav mx-auto">
                    <li class="nav-item"><a class="nav-link" href="/adminmembers">Members</a></li>
                    <li class="nav-item"><a class="nav-link active" href="/adminevents">Events</a></li>
                    <li class="nav-item"><a class="nav-link" href="/adminorganization">Organization</a></li>
                    <li class="nav-item"></li>
                </ul><a class="btn btn-primary shadow" role="button" href="/signup">Sign up</a>
            </div>
        </div>
    </nav>
    <section class="py-1">
        <div class="container container py-4 bg-dark">
            <div class="row mb-4 justify-content-center">
                <div class="col-md-10 col-xl-10 text-center mx-auto py-4">
                    <h1 class="fw-bold">Welcome to ORION&nbsp;</h1>
                    <p class="text-muted fs-5 mb-3">Get a comprehensive overview of the current status and activities within the organization.</p>
                </div>
            </div>
            <div class="row text-center mb-3 justify-content-center">
                <div class="col-md-3 mb-3">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Number of Members</h5>
                            <p class="card-text display-6">300</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Number of Events</h5>
                            <p class="card-text display-6">15</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Upcoming Events</h5>
                            <p class="card-text display-6">3</p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row text-center mb-3 justify-content-center">
                <div class="col-md-3 mb-3">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Member Growth</h5>
                            <canvas id="memberGrowthChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Events Over the Semester</h5>
                            <canvas id="eventsSemesterChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Event Feedback Scores</h5>
                            <canvas id="feedbackScoresChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row text-center mb-3 justify-content-center">
                <div class="col-md-3 mb-2">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Members from each Diploma</h5>
                            <canvas id="diplomaCourseChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="card shadow-sm border-light">
                        <div class="card-body">
                            <h5 class="card-title">Participants over the semester</h5>
                            <canvas id="participantsChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
    
    <footer class="bg-dark">
        <div class="container py-4 py-lg-5">
            <div class="row justify-content-center">
                <div class="col-sm-4 col-md-3 text-center text-lg-start d-flex flex-column">
                    <h3 class="fs-6 fw-bold">Special Interest Group</h3>
                    <ul class="list-unstyled">
                        <li><a href="/overflow">Overflow</a></li>
                        <li><a href="/orion">Orion</a></li>
                        <li><a href="/nullsec">Nullsec</a></li>
                    </ul>
                </div>
                <div class="col-sm-4 col-md-3 text-center text-lg-start d-flex flex-column">
                    <h3 class="fs-6 fw-bold">&nbsp;</h3>
                    <ul class="list-unstyled">
                        <li><a href="/ictsociety">ICT Society</a></li>
                        <li><a href="/aisig">AISIG</a></li>
                        <li><a href="/amphibi">Amphibi Studio</a></li>
                    </ul>
                </div>
                <div class="col-sm-4 col-md-3 text-center text-lg-start d-flex flex-column">
                    <h3 class="fs-6 fw-bold">&nbsp;</h3>
                    <ul class="list-unstyled">
                        <li><a href="/scs">SCS</a></li>
                        <li><a href="/thedot">The Dot</a></li>
                        <li><a href="/pvsig">PVSIG</a></li>
                    </ul>
                </div>
                <div class="col-lg-3 text-center text-lg-start d-flex flex-column align-items-center order-first align-items-lg-start order-lg-last">
                    <div class="fw-bold d-flex align-items-center mb-2"><span class="bs-icon-sm bs-icon-circle bs-icon-primary d-flex justify-content-center align-items-center bs-icon me-2"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="currentColor" viewBox="0 0 16 16" class="bi bi-bezier">
                                <path fill-rule="evenodd" d="M0 10.5A1.5 1.5 0 0 1 1.5 9h1A1.5 1.5 0 0 1 4 10.5v1A1.5 1.5 0 0 1 2.5 13h-1A1.5 1.5 0 0 1 0 11.5zm1.5-.5a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5zm10.5.5A1.5 1.5 0 0 1 13.5 9h1a1.5 1.5 0 0 1 1.5 1.5v1a1.5 1.5 0 0 1-1.5 1.5h-1a1.5 1.5 0 0 1-1.5-1.5zm1.5-.5a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5zM6 4.5A1.5 1.5 0 0 1 7.5 3h1A1.5 1.5 0 0 1 10 4.5v1A1.5 1.5 0 0 1 8.5 7h-1A1.5 1.5 0 0 1 6 5.5zM7.5 4a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5z"></path>
                                <path d="M6 4.5H1.866a1 1 0 1 0 0 1h2.668A6.517 6.517 0 0 0 1.814 9H2.5c.123 0 .244.015.358.043a5.517 5.517 0 0 1 3.185-3.185A1.503 1.503 0 0 1 6 5.5zm3.957 1.358A1.5 1.5 0 0 0 10 5.5v-1h4.134a1 1 0 1 1 0 1h-2.668a6.517 6.517 0 0 1 2.72 3.5H13.5c-.123 0-.243.015-.358.043a5.517 5.517 0 0 0-3.185-3.185z"></path>
                            </svg></span><span>OSCO</span></div>
                    <p class="text-muted">The Only All in One Community Organizer</p>
                </div>
            </div>
            <hr>
            <div class="text-muted d-flex justify-content-between align-items-center pt-3">
                <p class="mb-0">Copyright © 2024 OSCO</p>
                <ul class="list-inline mb-0">
                    <li class="list-inline-item"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="currentColor" viewBox="0 0 16 16" class="bi bi-facebook">
                            <path d="M16 8.049c0-4.446-3.582-8.05-8-8.05C3.58 0-.002 3.603-.002 8.05c0 4.017 2.926 7.347 6.75 7.951v-5.625h-2.03V8.05H6.75V6.275c0-2.017 1.195-3.131 3.022-3.131.876 0 1.791.157 1.791.157v1.98h-1.009c-.993 0-1.303.621-1.303 1.258v1.51h2.218l-.354 2.326H9.25V16c3.824-.604 6.75-3.934 6.75-7.951"></path>
                        </svg></li>
                    <li class="list-inline-item"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="currentColor" viewBox="0 0 16 16" class="bi bi-twitter">
                            <path d="M5.026 15c6.038 0 9.341-5.003 9.341-9.334 0-.14 0-.282-.006-.422A6.685 6.685 0 0 0 16 3.542a6.658 6.658 0 0 1-1.889.518 3.301 3.301 0 0 0 1.447-1.817 6.533 6.533 0 0 1-2.087.793A3.286 3.286 0 0 0 7.875 6.03a9.325 9.325 0 0 1-6.767-3.429 3.289 3.289 0 0 0 1.018 4.382A3.323 3.323 0 0 1 .64 6.575v.045a3.288 3.288 0 0 0 2.632 3.218 3.203 3.203 0 0 1-.865.115 3.23 3.23 0 0 1-.614-.057 3.283 3.283 0 0 0 3.067 2.277A6.588 6.588 0 0 1 .78 13.58a6.32 6.32 0 0 1-.78-.045A9.344 9.344 0 0 0 5.026 15"></path>
                        </svg></li>
                    <li class="list-inline-item"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="currentColor" viewBox="0 0 16 16" class="bi bi-instagram">
                            <path d="M8 0C5.829 0 5.556.01 4.703.048 3.85.088 3.269.222 2.76.42a3.917 3.917 0 0 0-1.417.923A3.927 3.927 0 0 0 .42 2.76C.222 3.268.087 3.85.048 4.7.01 5.555 0 5.827 0 8.001c0 2.172.01 2.444.048 3.297.04.852.174 1.433.372 1.942.205.526.478.972.923 1.417.444.445.89.719 1.416.923.51.198 1.09.333 1.942.372C5.555 15.99 5.827 16 8 16s2.444-.01 3.298-.048c.851-.04 1.434-.174 1.943-.372a3.916 3.916 0 0 0 1.416-.923c.445-.445.718-.891.923-1.417.197-.509.332-1.09.372-1.942C15.99 10.445 16 10.173 16 8s-.01-2.445-.048-3.299c-.04-.851-.175-1.433-.372-1.941a3.926 3.926 0 0 0-.923-1.417A3.911 3.911 0 0 0 13.24.42c-.51-.198-1.092-.333-1.943-.372C10.443.01 10.172 0 7.998 0h.003zm-.717 1.442h.718c2.136 0 2.389.007 3.232.046.78.035 1.204.166 1.486.275.373.145.64.319.92.599.28.28.453.546.598.92.11.281.24.705.275 1.485.039.843.047 1.096.047 3.231s-.008 2.389-.047 3.232c-.035.78-.166 1.203-.275 1.485a2.47 2.47 0 0 1-.599.919c-.28.28-.546.453-.92.598-.28.11-.704.24-1.485.276-.843.038-1.096.047-3.232.047s-2.39-.009-3.233-.047c-.78-.036-1.203-.166-1.485-.276a2.478 2.478 0 0 1-.92-.598 2.48 2.48 0 0 1-.6-.92c-.109-.281-.24-.705-.275-1.485-.038-.843-.046-1.096-.046-3.233 0-2.136.008-2.388.046-3.231.036-.78.166-1.204.276-1.486.145-.373.319-.64.599-.92.28-.28.546-.453.92-.598.282-.11.705-.24 1.485-.276.738-.034 1.024-.044 2.515-.045v.002zm4.988 1.328a.96.96 0 1 0 0 1.92.96.96 0 0 0 0-1.92zm-4.27 1.122a4.109 4.109 0 1 0 0 8.217 4.109 4.109 0 0 0 0-8.217zm0 1.441a2.667 2.667 0 1 1 0 5.334 2.667 2.667 0 0 1 0-5.334"></path>
                        </svg></li>
                </ul>
            </div>
        </div>
    </footer>
    <script src="assets/bootstrap/js/bootstrap.min.js"></script>
    <script>
        // Data for the charts
        const participantsData = {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            datasets: [{
                label: 'Participants',
                data: [12, 19, 3, 5, 2, 3, 7, 10, 5, 8, 15, 6],
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        };

        const diplomaCourseData = {
            labels: ['Information Technology', 'Cybersecurity', 'Immersive Media', 'Data Science'],
            datasets: [{
                label: 'Members',
                data: [30, 100, 25, 20],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.2)',
                    'rgba(54, 162, 235, 0.2)',
                    'rgba(255, 206, 86, 0.2)',
                    'rgba(75, 192, 192, 0.2)',
                    'rgba(153, 102, 255, 0.2)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        };

        const memberGrowthData = {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            datasets: [{
                label: 'Member Growth',
                data: [200, 210, 220, 240, 250, 265, 275, 290, 310, 320, 330, 350],
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        };

        const feedbackScoresData = {
            labels: ['Event 1', 'Event 2', 'Event 3', 'Event 4', 'Event 5','Event 6', 'Event 7', 'Event 8', 'Event 9', 'Event `10`'],
            datasets: [{
                label: 'Feedback Scores',
                data: [4.5, 3.8, 2.2, 4.7, 3.3, 3.5, 4.8, 3.2, 3.7, 5.0],
                backgroundColor: 'rgba(255, 206, 86, 0.2)',
                borderColor: 'rgba(255, 206, 86, 1)',
                borderWidth: 1
            }]
        };

        const eventsSemesterData = {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            datasets: [{
                label: 'Events',
                data: [1, 2, 3, 4, 2, 1, 3, 4, 5, 2, 1, 3], // Sample data, update as needed
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1
            }]
        };

        const ctxEventsSemester = document.getElementById('eventsSemesterChart').getContext('2d');
        const eventsSemesterChart = new Chart(ctxEventsSemester, {
            type: 'line',
            data: eventsSemesterData,
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });


        // Create the charts
        const ctxParticipants = document.getElementById('participantsChart').getContext('2d');
        const participantsChart = new Chart(ctxParticipants, {
            type: 'line',
            data: participantsData,
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        const ctxDiplomaCourse = document.getElementById('diplomaCourseChart').getContext('2d');
        const diplomaCourseChart = new Chart(ctxDiplomaCourse, {
            type: 'pie',
            data: diplomaCourseData
        });

        const ctxMemberGrowth = document.getElementById('memberGrowthChart').getContext('2d');
        const memberGrowthChart = new Chart(ctxMemberGrowth, {
            type: 'line',
            data: memberGrowthData,
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        const ctxFeedbackScores = document.getElementById('feedbackScoresChart').getContext('2d');
        const feedbackScoresChart = new Chart(ctxFeedbackScores, {
            type: 'bar',
            data: feedbackScoresData,
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    </script>
</body>

</html>
