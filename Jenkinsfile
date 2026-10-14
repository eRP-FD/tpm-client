// (C) Copyright IBM Deutschland GmbH 2021, 2023
// (C) Copyright IBM Corp 2021, 2023
//
// non-exclusively licensed to gematik GmbH

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pipeline {
    agent {
        node {
            label 'master'
        }
    }
    options {
        disableConcurrentBuilds()
        skipDefaultCheckout()
    }
    tools {
        jdk 'jdk_17'
    }
    environment {
        ENABLE_GRADLE_BUILD_CACHE = 'true'
        ENABLE_GRADLE_CONFIG_CACHE = 'true' // gradle 6+
        WARN_GRADLE_CONFIG_CACHE_PROBLEMS = 'true' // do not fail builds for config cache unsupported tasks
    }
    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                commonCheckout()
            }
        }

        stage('Create Release') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                gradleCreateReleaseEpa()
            }
        }

        stage('SBOM and Sonar') {
            steps {
                 withVault(
                    [[path: "secret/eRp/dependencytrack", secretValues: [[vaultKey: 'dependencytrack_apikey', envVar: 'DEPENDENCYTRACK_APIKEY']]],
                        [path: "secret/eRp/dependencytrack", secretValues: [[vaultKey: 'frontend_url', envVar: 'DEPENDENCYTRACK_FRONTEND_URL']]],
                        [path: "secret/eRp/dependencytrack", secretValues: [[vaultKey: 'serverhostname', envVar: 'DEPENDENCYTRACK_SERVER_HOSTNAME']]],
                        [path: "secret/eRp/sonarqube", secretValues: [[vaultKey: 'sonarqubetoken', envVar: 'SONARQUBE_TOKEN']]],
                        [path: "secret/eRp/sonarqube", secretValues: [[vaultKey: 'sonarqubeurl', envVar: 'SONARQUBE_URL']]]
                        ]

                 ) {
                    staticAnalysis()
                    dependencyTrack()
                }
            }
        }

        stage('SBOM') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: 'jenkins-github-erp', usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        sbomSyft(
                            DOCKER_OPTS:'--build-arg CONAN_LOGIN_USERNAME="${NEXUS_USERNAME}" --build-arg CONAN_PASSWORD="${NEXUS_PASSWORD}"',
                            DOCKER_FILE:'docker/Dockerfile'
                        )
                    }
                }
            }
        }

        stage('Check Container Build') {
            when {
                not {
                    anyOf {
                        branch 'master'
                        branch 'release/*'
                    }
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: 'jenkins-github-erp', usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        checkDockerBuild(
                            DOCKER_OPTS:'--build-arg CONAN_LOGIN_USERNAME="${NEXUS_USERNAME}" --build-arg CONAN_PASSWORD="${NEXUS_PASSWORD}"',
                            DOCKER_FILE:'docker/Dockerfile'
                        )
                    }
                }
            }
        }

        stage('Build Container') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: 'jenkins-github-erp', usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        buildAndPushContainer(
                            DOCKER_OPTS:'--build-arg CONAN_LOGIN_USERNAME="${NEXUS_USERNAME}" --build-arg CONAN_PASSWORD="${NEXUS_PASSWORD}"',
                            DOCKER_FILE:'docker/Dockerfile'
                        )
                    }
                }
            }
        }

        stage('Publish Release') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                finishRelease()
            }
        }

        stage ("Publish to Nexus") {
            agent {
                docker {
                    label 'dockerstage'
                    image 'conanio/gcc10:latest'
                    reuseNode true
                    args '-u root:sudo'
                }
            }
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                script {
                    loadNexusConfiguration {
                        sh '''
                            git config --global --add safe.directory '*'
                            conan remote clean &&\
                            conan remote add erp-conan-2 https://artifactory-cpp-ce.ihc-devops.net/artifactory/api/conan/erp-conan-2 true --force &&\
                            conan user -r erp-conan-2 -p "${NEXUS_PASSWORD}" "${NEXUS_USERNAME}" &&\
                            conan export . &&\
                            conan export . tpmclient/latest@_/_ &&\
                            conan upload --remote erp-conan-2 --confirm tpmclient
                        '''
                    }
                }
            }
        }

        stage('Deployment to dev') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                script {
                    if (env.BRANCH_NAME == 'master') {
                        triggerDeployment('targetEnvironment': 'dev2')
                    } else if (env.BRANCH_NAME.startsWith('release/1.0.')) {
                        triggerDeployment('targetEnvironment': 'dev')
                    }
                }
            }
        }
    }
}
