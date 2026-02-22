# Testing.cmake - Test infrastructure configuration

include(CTest)

option(BUILD_TESTING "Build tests" ON)

if(BUILD_TESTING)
    enable_testing()

    # Test output directory
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_TEST ${CMAKE_BINARY_DIR}/tests)

    # Custom target for running all tests
    add_custom_target(check
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running all tests..."
    )

    # Custom target for running unit tests only
    add_custom_target(check-unit
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L unit
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running unit tests..."
    )

    # Custom target for running integration tests only
    add_custom_target(check-integration
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L integration
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running integration tests..."
    )

    # Custom target for running conformance tests only
    add_custom_target(check-conformance
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L conformance
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running conformance tests..."
    )

    # Helper function to add a unit test
    function(sol_add_unit_test name)
        set(options "")
        set(oneValueArgs "")
        set(multiValueArgs SOURCES LIBS)
        cmake_parse_arguments(TEST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

        add_executable(test_${name} ${TEST_SOURCES})
        target_link_libraries(test_${name} PRIVATE ${TEST_LIBS})

        add_test(
            NAME unit_${name}
            COMMAND test_${name}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )

        set_tests_properties(unit_${name} PROPERTIES LABELS "unit")
    endfunction()

    # Helper function to add an integration test
    function(sol_add_integration_test name)
        set(options "")
        set(oneValueArgs TIMEOUT)
        set(multiValueArgs SOURCES LIBS)
        cmake_parse_arguments(TEST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

        add_executable(itest_${name} ${TEST_SOURCES})
        target_link_libraries(itest_${name} PRIVATE ${TEST_LIBS})

        if(NOT TEST_TIMEOUT)
            set(TEST_TIMEOUT 60)
        endif()

        add_test(
            NAME integration_${name}
            COMMAND itest_${name}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )

        set_tests_properties(integration_${name} PROPERTIES
            LABELS "integration"
            TIMEOUT ${TEST_TIMEOUT}
        )
    endfunction()

    # Helper function to add a conformance test
    function(sol_add_conformance_test name)
        set(options "")
        set(oneValueArgs FIXTURE_DIR TIMEOUT)
        set(multiValueArgs SOURCES LIBS)
        cmake_parse_arguments(TEST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

        add_executable(ctest_${name} ${TEST_SOURCES})
        target_link_libraries(ctest_${name} PRIVATE ${TEST_LIBS})

        if(NOT TEST_TIMEOUT)
            set(TEST_TIMEOUT 300)
        endif()

        add_test(
            NAME conformance_${name}
            COMMAND ctest_${name} ${TEST_FIXTURE_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )

        set_tests_properties(conformance_${name} PROPERTIES
            LABELS "conformance"
            TIMEOUT ${TEST_TIMEOUT}
        )
    endfunction()

    message(STATUS "Testing enabled")
endif()
